import streamlit as st
import pandas as pd
from openpyxl import load_workbook
from PIL import Image, UnidentifiedImageError, ImageFilter
import imagehash
import io
import os
import re
import sqlite3
import zipfile
import hashlib
import requests
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import math

# =========================
# CONFIG UI
# =========================
st.set_page_config(page_title="Audit Foto Patroli", layout="wide")
st.title("🕵️ AUDIT FOTO PATROLI")
st.caption("Audit foto patroli yang terduplicate. Logo/header/template akan tidak akan ter-audit.")

# =========================
# SIDEBAR FILTER (ANTI LOGO / ANOMALI)
# =========================
st.sidebar.header("⚙️ Filter Foto Patroli (Anti Logo/Template)")

MIN_W = st.sidebar.number_input("Min lebar (px)", 100, 5000, 600, 50)
MIN_H = st.sidebar.number_input("Min tinggi (px)", 100, 5000, 450, 50)

# Logo/banner sering sangat lebar
MAX_BANNER_AR = st.sidebar.slider("Max aspect ratio banner (W/H)", 1.0, 10.0, 3.2, 0.1)

# Entropy rendah biasanya logo/flat design
MIN_ENTROPY = st.sidebar.slider("Min entropy (keragaman warna)", 0.0, 10.0, 4.2, 0.1)

# Edge density rendah biasanya logo / gambar flat
MIN_EDGE_DENSITY = st.sidebar.slider("Min edge density (detail)", 0.0, 1.0, 0.08, 0.01)

# Opsional: keyword pada segment untuk di-skip (kalau format kamu punya baris “cover/logo”)
skip_keyword = st.sidebar.text_input("Skip bila Segment mengandung (opsional)", value="logo,cover,header,template")
SKIP_SEGMENT_KEYWORDS = [k.strip().lower() for k in skip_keyword.split(",") if k.strip()]

st.sidebar.caption("Tip: Kalau banyak foto map/geo ikut ke-skip, turunkan min edge density atau min entropy sedikit.")

# =========================
# DATABASE
# =========================
DB_PATH = "audit_history.db"

def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS history (
            sha256 TEXT PRIMARY KEY,
            phash  TEXT,
            source_type TEXT,
            source_file TEXT,
            sheet TEXT,
            location TEXT,
            cluster TEXT,
            segment TEXT,
            url TEXT,
            first_seen DATE
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_phash ON history(phash)")
    return conn

def db_lookup(conn, sha256_hex: str, phash_str: str):
    exact = conn.execute(
        "SELECT source_file, sheet, location, cluster, segment, url, first_seen FROM history WHERE sha256=?",
        (sha256_hex,)
    ).fetchone()

    ph = conn.execute(
        "SELECT source_file, sheet, location, cluster, segment, url, first_seen FROM history WHERE phash=? LIMIT 1",
        (phash_str,)
    ).fetchone()

    return exact, ph

def db_insert(conn, row: dict):
    conn.execute("""
        INSERT OR IGNORE INTO history
        (sha256, phash, source_type, source_file, sheet, location, cluster, segment, url, first_seen)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        row["sha256"], row["phash"], row["source_type"], row["source_file"],
        row["sheet"], row["location"], row["cluster"], row["segment"], row["url"], row["first_seen"]
    ))

# =========================
# IMAGE QUALITY / CLASSIFIER (SKIP LOGO / TEMPLATE)
# =========================
def image_entropy(img: Image.Image) -> float:
    """Shannon entropy from grayscale histogram (0..~8 for typical images)."""
    g = img.convert("L")
    hist = g.histogram()
    total = sum(hist)
    if total == 0:
        return 0.0
    ent = 0.0
    for h in hist:
        if h:
            p = h / total
            ent -= p * math.log2(p)
    return ent

def edge_density(img: Image.Image) -> float:
    """
    Approx edge density: apply FIND_EDGES then mean intensity / 255.
    Lower = flat image (often logo/template).
    """
    g = img.convert("L").filter(ImageFilter.FIND_EDGES)
    # downscale for speed
    g = g.resize((256, 256))
    px = list(g.getdata())
    mean = sum(px) / len(px)
    return mean / 255.0

def should_skip_image(img: Image.Image, segment_text: str) -> tuple[bool, str]:
    w, h = img.size
    if w < MIN_W or h < MIN_H:
        return True, f"SKIP: ukuran kecil ({w}x{h})"

    ar = w / max(h, 1)
    if ar > MAX_BANNER_AR:
        return True, f"SKIP: banner/logo aspect ratio ({ar:.2f})"

    ent = image_entropy(img)
    if ent < MIN_ENTROPY:
        return True, f"SKIP: entropy rendah ({ent:.2f})"

    ed = edge_density(img)
    if ed < MIN_EDGE_DENSITY:
        return True, f"SKIP: detail rendah (edge {ed:.2f})"

    seg = (segment_text or "").strip().lower()
    if seg and SKIP_SEGMENT_KEYWORDS:
        if any(k in seg for k in SKIP_SEGMENT_KEYWORDS):
            return True, "SKIP: segment keyword"

    return False, ""

# =========================
# HASHING
# =========================
def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def compute_hashes(img: Image.Image, raw_bytes: bytes):
    # thumbnail for speed + preview
    thumb = img.copy()
    thumb.thumbnail((240, 240))
    ph = str(imagehash.phash(thumb))
    sh = sha256_bytes(raw_bytes)
    return sh, ph, thumb

# =========================
# GOOGLE LINK HANDLING
# =========================
DOC_ID_RE = re.compile(r"/document/d/([a-zA-Z0-9_-]+)")
DRIVE_FILE_ID_RE = re.compile(r"/file/d/([a-zA-Z0-9_-]+)")
GENERIC_ID_RE = re.compile(r"(?:id=)([a-zA-Z0-9_-]+)")

def build_gdocs_export_docx_url(doc_id: str) -> str:
    return f"https://docs.google.com/document/d/{doc_id}/export?format=docx"

def build_drive_download_url(file_id: str) -> str:
    return f"https://drive.google.com/uc?export=download&id={file_id}"

def http_get_bytes(session: requests.Session, url: str, timeout=25):
    try:
        r = session.get(url, timeout=timeout, stream=True, allow_redirects=True)
        if r.status_code != 200:
            return None
        return r.content
    except requests.RequestException:
        return None

def extract_images_from_docx_bytes(docx_bytes: bytes) -> list[bytes]:
    out = []
    with zipfile.ZipFile(io.BytesIO(docx_bytes), "r") as z:
        for name in z.namelist():
            if name.startswith("word/media/"):
                try:
                    out.append(z.read(name))
                except:
                    pass
    return out

def download_images_from_url(session: requests.Session, url: str) -> list[bytes]:
    if not url or not isinstance(url, str):
        return []

    m = DOC_ID_RE.search(url)
    if m:
        doc_id = m.group(1)
        docx_bytes = http_get_bytes(session, build_gdocs_export_docx_url(doc_id))
        if not docx_bytes:
            return []
        return extract_images_from_docx_bytes(docx_bytes)

    m = DRIVE_FILE_ID_RE.search(url)
    if m:
        b = http_get_bytes(session, build_drive_download_url(m.group(1)))
        return [b] if b else []

    m = GENERIC_ID_RE.search(url)
    if m and "google" in url:
        b = http_get_bytes(session, build_drive_download_url(m.group(1)))
        return [b] if b else []

    return []

# =========================
# EXCEL PARSING
# =========================
def find_header_row_and_cols(ws, max_scan_rows=40):
    target = {"cluster": ["cluster"], "segment": ["segment", "segment name", "segmen"], "link": ["link", "url"]}
    def norm(v): return str(v).strip().lower() if v is not None else ""

    for r in range(1, min(max_scan_rows, ws.max_row) + 1):
        row_vals = [norm(ws.cell(r, c).value) for c in range(1, min(ws.max_column, 30) + 1)]
        if not any(row_vals): continue

        col_cluster = col_segment = col_link = None
        for idx, val in enumerate(row_vals, start=1):
            if any(k in val for k in target["cluster"]): col_cluster = idx
            if any(k in val for k in target["segment"]): col_segment = idx
            if any(k in val for k in target["link"]): col_link = idx

        if col_cluster and col_segment and col_link:
            return r, col_cluster, col_segment, col_link

    return 4, 2, 3, 7

def extract_embedded_images(wb, source_file_name: str):
    items = []
    for ws in wb.worksheets:
        imgs = getattr(ws, "_images", [])
        if not imgs:
            continue

        header_row, col_cluster, col_segment, _ = find_header_row_and_cols(ws)

        for img_obj in imgs:
            try:
                row = img_obj.anchor._from.row + 1
                col = img_obj.anchor._from.col + 1
                cluster = ws.cell(row=row, column=col_cluster).value or "N/A"
                segment = ws.cell(row=row, column=col_segment).value or "N/A"

                raw = img_obj._data()
                img = Image.open(io.BytesIO(raw)).convert("RGB")

                skip, reason = should_skip_image(img, str(segment))
                if skip:
                    items.append({
                        "source_type": "EmbeddedExcel",
                        "source_file": source_file_name,
                        "sheet": ws.title,
                        "location": f"R{row}C{col}",
                        "cluster": str(cluster),
                        "segment": str(segment),
                        "url": "",
                        "sha256": "",
                        "phash": "",
                        "status_akhir": "⏭️ SKIP (Non-Patroli)",
                        "skip_reason": reason,
                        "thumb": img.resize((240, int(240*img.size[1]/max(img.size[0],1))))
                    })
                    continue

                sh, ph, thumb = compute_hashes(img, raw)
                items.append({
                    "source_type": "EmbeddedExcel",
                    "source_file": source_file_name,
                    "sheet": ws.title,
                    "location": f"R{row}C{col}",
                    "cluster": str(cluster),
                    "segment": str(segment),
                    "url": "",
                    "sha256": sh,
                    "phash": ph,
                    "status_akhir": "",
                    "skip_reason": "",
                    "thumb": thumb
                })
            except:
                continue
    return items

def extract_link_images(wb, source_file_name: str, max_workers=12):
    items = []
    jobs = []

    for ws in wb.worksheets:
        header_row, col_cluster, col_segment, col_link = find_header_row_and_cols(ws)
        for r in range(header_row + 1, ws.max_row + 1):
            url = ws.cell(r, col_link).value
            if not url:
                continue
            url = str(url)
            if "google" not in url:
                continue
            cluster = ws.cell(r, col_cluster).value or "N/A"
            segment = ws.cell(r, col_segment).value or "N/A"
            jobs.append((ws.title, r, col_link, str(cluster), str(segment), url))

    if not jobs:
        return items

    session = requests.Session()
    session.headers.update({"User-Agent": "PatrolPhotoAudit/1.0"})

    def worker(job):
        sheet, r, col_link, cluster, segment, url = job
        img_bytes_list = download_images_from_url(session, url)

        out = []
        for idx, b in enumerate(img_bytes_list, start=1):
            if not b:
                continue
            try:
                img = Image.open(io.BytesIO(b)).convert("RGB")
            except UnidentifiedImageError:
                continue

            skip, reason = should_skip_image(img, segment)
            if skip:
                out.append({
                    "source_type": "CloudLink",
                    "source_file": source_file_name,
                    "sheet": sheet,
                    "location": f"R{r}C{col_link}#IMG{idx}",
                    "cluster": cluster,
                    "segment": segment,
                    "url": url,
                    "sha256": "",
                    "phash": "",
                    "status_akhir": "⏭️ SKIP (Non-Patroli)",
                    "skip_reason": reason,
                    "thumb": img.resize((240, int(240*img.size[1]/max(img.size[0],1))))
                })
                continue

            sh, ph, thumb = compute_hashes(img, b)
            out.append({
                "source_type": "CloudLink",
                "source_file": source_file_name,
                "sheet": sheet,
                "location": f"R{r}C{col_link}#IMG{idx}",
                "cluster": cluster,
                "segment": segment,
                "url": url,
                "sha256": sh,
                "phash": ph,
                "status_akhir": "",
                "skip_reason": "",
                "thumb": thumb
            })
        return out

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = [ex.submit(worker, j) for j in jobs]
        for f in as_completed(futures):
            try:
                items.extend(f.result())
            except:
                pass

    return items

# =========================
# AUDIT LOGIC
# =========================
def audit_workbook(xlsx_path: str):
    wb = load_workbook(xlsx_path, data_only=True)
    source_file_name = os.path.basename(xlsx_path)

    items = extract_embedded_images(wb, source_file_name) + extract_link_images(wb, source_file_name)
    df = pd.DataFrame(items)
    if df.empty:
        return df

    # Pisahkan yang SKIP (tidak ikut audit hash)
    is_skip = df["status_akhir"].astype(str).str.startswith("⏭️ SKIP")
    df_audit = df[~is_skip].copy()
    df_skip = df[is_skip].copy()

    if df_audit.empty:
        # semua skip
        return df

    # internal dup exact/phash
    df_audit["dup_internal_exact"] = df_audit.duplicated("sha256", keep="first")
    df_audit["dup_internal_phash"] = df_audit.duplicated("phash", keep="first")

    conn = get_db()
    today = datetime.now().strftime("%Y-%m-%d")
    df_audit["first_seen"] = today

    hist_status, hist_detail = [], []
    for _, row in df_audit.iterrows():
        exact, ph = db_lookup(conn, row["sha256"], row["phash"])
        if exact:
            hist_status.append("REUPLOAD_EXACT")
            hist_detail.append(f"Pernah terbit {exact[-1]} | {exact[0]} | {exact[1]} | {exact[2]}")
        elif ph:
            hist_status.append("REUPLOAD_SIMILAR_PHASH")
            hist_detail.append(f"Mirip phash: {ph[-1]} | {ph[0]} | {ph[1]} | {ph[2]}")
        else:
            hist_status.append("NEW")
            hist_detail.append("")
    df_audit["history_status"] = hist_status
    df_audit["history_detail"] = hist_detail

    def decide(r):
        if r["history_status"] == "REUPLOAD_EXACT":
            return "❌ GUGUR (Pernah Terbit - Exact)"
        if r["history_status"] == "REUPLOAD_SIMILAR_PHASH":
            return "⚠️ CEK MANUAL (Mirip Foto Lama)"
        if r["dup_internal_exact"]:
            return "❌ GUGUR (Duplikat di File Ini - Exact)"
        if r["dup_internal_phash"]:
            return "⚠️ CEK MANUAL (Duplikat Mirip di File Ini)"
        return "✅ VALID"

    df_audit["status_akhir"] = df_audit.apply(decide, axis=1)

    # Simpan hanya VALID ke DB
    for _, r in df_audit[df_audit["status_akhir"] == "✅ VALID"].iterrows():
        db_insert(conn, {
            "sha256": r["sha256"],
            "phash": r["phash"],
            "source_type": r["source_type"],
            "source_file": r["source_file"],
            "sheet": r["sheet"],
            "location": r["location"],
            "cluster": r["cluster"],
            "segment": r["segment"],
            "url": r["url"],
            "first_seen": r["first_seen"]
        })
    conn.commit()
    conn.close()

    # Gabung kembali
    # Pastikan kolom ada semua
    for col in ["dup_internal_exact","dup_internal_phash","history_status","history_detail","first_seen"]:
        if col not in df_skip.columns:
            df_skip[col] = ""
    out = pd.concat([df_audit, df_skip], ignore_index=True)
    return out

# =========================
# STREAMLIT UI
# =========================
uploaded = st.file_uploader("Upload Excel Patroli (.xlsx)", type=["xlsx"])

colA, colB = st.columns([1, 2])
with colA:
    preview_limit = st.number_input("Maks preview gambar", min_value=0, max_value=500, value=120, step=10)
with colB:
    st.info("SKIP otomatis untuk logo/header/template berdasarkan ukuran, aspect ratio, entropy, dan detail (edge).")

if uploaded:
    tmp_path = "temp_upload.xlsx"
    with open(tmp_path, "wb") as f:
        f.write(uploaded.getbuffer())

    if st.button("🚀 MULAI AUDIT"):
        with st.status("Meng-audit foto…", expanded=True) as status:
            df = audit_workbook(tmp_path)

            if df.empty:
                status.update(label="Tidak ada foto yang terbaca.", state="error")
                st.warning("Tidak ditemukan foto embedded atau foto dari link Google yang bisa diproses.")
            else:
                status.update(label="Audit selesai.", state="complete")

                # Ringkasan
                st.subheader("Ringkasan")
                c1, c2, c3, c4, c5 = st.columns(5)
                c1.metric("Total Terdeteksi", len(df))
                c2.metric("VALID", int((df["status_akhir"] == "✅ VALID").sum()))
                c3.metric("GUGUR", int(df["status_akhir"].astype(str).str.contains("GUGUR").sum()))
                c4.metric("CEK MANUAL", int(df["status_akhir"].astype(str).str.contains("CEK MANUAL").sum()))
                c5.metric("SKIP", int(df["status_akhir"].astype(str).str.startswith("⏭️ SKIP").sum()))

                # Laporan
                st.subheader("Laporan")
                report = df.drop(columns=["thumb"], errors="ignore")
                st.dataframe(report, use_container_width=True)

                # Download
                out = io.BytesIO()
                report.to_excel(out, index=False)
                today = datetime.now().strftime("%Y-%m-%d")
                st.download_button(
                    "📥 Download Laporan (Excel)",
                    data=out.getvalue(),
                    file_name=f"Laporan_Audit_Foto_{today}.xlsx",
                    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                )

                # Preview
                st.subheader("Preview Foto (dibatasi)")
                shown = 0
                cols = st.columns(4)
                # prioritaskan yang bukan VALID dulu
                df_view = df.copy()
                priority = df_view["status_akhir"].map(lambda s: 0 if "GUGUR" in str(s) or "CEK MANUAL" in str(s) else (1 if "SKIP" in str(s) else 2))
                df_view = df_view.assign(_prio=priority).sort_values("_prio").drop(columns=["_prio"])

                for _, r in df_view.iterrows():
                    if preview_limit == 0 or shown >= preview_limit:
                        break
                    if r.get("thumb") is None:
                        continue
                    with cols[shown % 4]:
                        st.image(r["thumb"], caption=f'{r["sheet"]} | {r["location"]}\n{r["status_akhir"]}')
                        if r.get("skip_reason"):
                            st.caption(r["skip_reason"])
                        if r.get("history_detail"):
                            st.caption(r["history_detail"])
                    shown += 1

    if os.path.exists(tmp_path):
        os.remove(tmp_path)

st.divider()
st.caption(f"DB history disimpan lokal: {DB_PATH} (jangan dihapus kalau mau deteksi lintas bulan)")
