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
st.caption(
    "Audit foto patroli yang ter-duplicate (Embedded Excel + Google Docs/Drive). Set maks. preview gambar 500."
)

# =========================
# STREAMLIT UI (UPLOADER DI ATAS BIAR NGGAK HILANG)
# =========================
uploaded = st.file_uploader("Upload Excel Patroli (.xlsx)", type=["xlsx"])

colA, colB = st.columns([1, 2])
with colA:
    preview_limit = st.number_input("Maks preview gambar", min_value=0, max_value=500, value=120, step=10)
with colB:
    st.info("Reset history ada di sidebar kiri. Logo-only tidak ikut audit, GEO overlay akan diaudit.")

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
# RESET / HAPUS HISTORY AUDIT (SIDEBAR)
# =========================
st.sidebar.subheader("🧹 Reset History Audit")
confirm_reset = st.sidebar.checkbox("Saya yakin mau hapus total history", value=False)

if st.sidebar.button("🗑️ HAPUS TOTAL HISTORY (RESET)"):
    if not confirm_reset:
        st.sidebar.warning("Centang konfirmasi dulu.")
    else:
        try:
            if os.path.exists(DB_PATH):
                os.remove(DB_PATH)
                st.sidebar.success("✅ History dihapus. App akan refresh.")
                st.rerun()
            else:
                st.sidebar.info("ℹ️ History sudah kosong (file DB tidak ada).")
        except Exception as e:
            st.sidebar.error(f"❌ Gagal hapus DB: {e}")

# =========================
# HASHING
# =========================
def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def compute_hashes_from_bytes(img_bytes: bytes):
    try:
        img = Image.open(io.BytesIO(img_bytes)).convert("RGB")
    except UnidentifiedImageError:
        return None, None, None, None
    thumb = img.copy()
    thumb.thumbnail((240, 240))
    ph = str(imagehash.phash(thumb))
    sh = sha256_bytes(img_bytes)
    return sh, ph, thumb, img

# =========================
# HELPER: METRIK GLOBAL (UNTUK DETEKSI LOGO-ONLY)
# =========================
def image_entropy_gray(img: Image.Image) -> float:
    g = img.convert("L").resize((256, 256))
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
    g = img.convert("L").resize((256, 256)).filter(ImageFilter.FIND_EDGES)
    px = list(g.getdata())
    mean = sum(px) / (len(px) or 1)
    return mean / 255.0

def is_logo_only(img: Image.Image) -> tuple[bool, str]:
    """
    Deteksi gambar 'logo doang' / banner doang:
    cirinya: entropi rendah + edge rendah (flat), biasanya background putih/solid.
    Foto GEO/pemandangan biasanya entropi & edge lebih tinggi, jadi aman.
    """
    w, h = img.size
    if w < 120 or h < 120:
        return True, "LogoOnly: terlalu kecil"

    ent = image_entropy_gray(img)
    ed = edge_density(img)

    # Threshold ini sengaja dibuat cukup ketat supaya foto GEO tidak ikut ke-skip.
    # Logo-only biasanya entropi rendah dan edge rendah.
    if ent < 3.2 and ed < 0.035:
        return True, f"LogoOnly: ent={ent:.2f}, edge={ed:.3f}"

    # Extra: kalau sebagian besar gambar putih polos (background), cenderung logo-only
    g = img.convert("L").resize((256, 256))
    px = list(g.getdata())
    bright_ratio = sum(1 for p in px if p >= 240) / (len(px) or 1)
    if bright_ratio > 0.60 and ed < 0.040:
        return True, f"LogoOnly: bright={bright_ratio:.2f}, edge={ed:.3f}"

    return False, f"NotLogo: ent={ent:.2f}, edge={ed:.3f}"

# =========================
# DETEKSI GEO OVERLAY (SCAN BAWAH)
# =========================
def _patch_stats(patch_gray: Image.Image):
    px = list(patch_gray.getdata())
    n = len(px) or 1
    mean = sum(px) / n
    var = sum((p - mean) ** 2 for p in px) / n
    std = math.sqrt(var)
    white_ratio = sum(1 for p in px if p >= 220) / n
    dark_ratio  = sum(1 for p in px if p <= 70) / n
    return mean, std, white_ratio, dark_ratio

def overlay_geo_best(img: Image.Image) -> tuple[bool, str]:
    """
    Scan 3 area bawah: kiri, tengah, kanan (karena overlay bisa pindah posisi).
    Rule: minimal 2 dari 3 indikator:
      - white text ratio
      - dark box ratio
      - contrast (std)
    """
    w, h = img.size
    if w < 240 or h < 240:
        return False, "NonGEO: ukuran kecil"

    rois = [
        ("LB", (0.00, 0.65, 0.45, 1.00)),
        ("MB", (0.25, 0.65, 0.75, 1.00)),
        ("RB", (0.55, 0.65, 1.00, 1.00)),
    ]

    best_score = -1
    best_dbg = ""

    for name, (x0, y0, x1, y1) in rois:
        X0 = int(w * x0); Y0 = int(h * y0)
        X1 = int(w * x1); Y1 = int(h * y1)

        patch = img.crop((X0, Y0, X1, Y1)).convert("L").resize((240, 240))
        mean, std, white_ratio, dark_ratio = _patch_stats(patch)

        has_white_text = white_ratio >= 0.004
        has_dark_box   = dark_ratio  >= 0.008
        has_contrast   = std >= 16

        score = int(has_white_text) + int(has_dark_box) + int(has_contrast)
        dbg = f"{name}: mean={mean:.1f}, std={std:.1f}, white={white_ratio:.3f}, dark={dark_ratio:.3f}, score={score}"

        if score > best_score:
            best_score = score
            best_dbg = dbg

    if best_score >= 2:
        return True, f"GEO✅ ({best_dbg})"
    return False, f"NonGEO ({best_dbg})"

def classify_for_audit(img: Image.Image) -> tuple[bool, str, str]:
    """
    RULE FINAL (sesuai komplain kamu):
    1) Kalau LOGO-ONLY -> SKIP (tidak audit, tidak valid/gugur)
    2) Kalau bukan logo-only:
       - Ada GEO overlay -> AUDIT (valid/gugur) walau ada logo perusahaan
       - Tidak ada GEO -> SKIP
    """
    logo, logo_dbg = is_logo_only(img)
    if logo:
        return False, "⏭️ SKIP (Logo-Only)", logo_dbg

    ok, geo_dbg = overlay_geo_best(img)
    if ok:
        return True, "", ""
    return False, "⏭️ SKIP (Non-Patroli)", geo_dbg

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

def http_get_bytes(url: str, timeout=25):
    try:
        r = requests.get(url, timeout=timeout, stream=True, allow_redirects=True)
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

def download_images_from_url(url: str) -> list[bytes]:
    if not url or not isinstance(url, str):
        return []

    m = DOC_ID_RE.search(url)
    if m:
        doc_id = m.group(1)
        docx_bytes = http_get_bytes(build_gdocs_export_docx_url(doc_id))
        if not docx_bytes:
            return []
        return extract_images_from_docx_bytes(docx_bytes)

    m = DRIVE_FILE_ID_RE.search(url)
    if m:
        b = http_get_bytes(build_drive_download_url(m.group(1)))
        return [b] if b else []

    m = GENERIC_ID_RE.search(url)
    if m and "google" in url:
        b = http_get_bytes(build_drive_download_url(m.group(1)))
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
        if not any(row_vals):
            continue

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
                sh, ph, thumb, full_img = compute_hashes_from_bytes(raw)
                if full_img is None:
                    continue

                audit_ok, skip_status, skip_reason = classify_for_audit(full_img)
                if not audit_ok:
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
                        "status_akhir": skip_status,
                        "skip_reason": skip_reason,
                        "thumb": thumb
                    })
                    continue

                # masuk audit
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

    items = []
    if not jobs:
        return items

    def worker(job):
        sheet, r, col_link, cluster, segment, url = job
        img_bytes_list = download_images_from_url(url)

        out = []
        for idx, b in enumerate(img_bytes_list, start=1):
            if not b:
                continue
            sh, ph, thumb, full_img = compute_hashes_from_bytes(b)
            if full_img is None:
                continue

            audit_ok, skip_status, skip_reason = classify_for_audit(full_img)
            if not audit_ok:
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
                    "status_akhir": skip_status,
                    "skip_reason": skip_reason,
                    "thumb": thumb
                })
                continue

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

    df = pd.DataFrame(extract_embedded_images(wb, source_file_name) + extract_link_images(wb, source_file_name))
    if df.empty:
        return df

    # yang benar-benar masuk audit: status_akhir kosong + sha256 ada
    audited_mask = (df["status_akhir"].astype(str).str.strip() == "") & (df["sha256"].astype(str).str.strip() != "")
    df_audit = df[audited_mask].copy()
    df_skip = df[~audited_mask].copy()

    if df_audit.empty:
        for col in ["dup_internal_exact","dup_internal_phash","history_status","history_detail","first_seen"]:
            df[col] = ""
        return df

    # duplikat internal
    df_audit["dup_internal_exact"] = df_audit.duplicated("sha256", keep="first")
    df_audit["dup_internal_phash"] = df_audit.duplicated("phash", keep="first")

    conn = get_db()
    today = datetime.now().strftime("%Y-%m-%d")
    df_audit["first_seen"] = today

    # history check
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

    # simpan hanya VALID ke history
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

    # rapihin kolom skip
    for col in ["dup_internal_exact","dup_internal_phash","history_status","history_detail","first_seen"]:
        if col not in df_skip.columns:
            df_skip[col] = ""

    return pd.concat([df_audit, df_skip], ignore_index=True)

# =========================
# RUN UI ACTIONS
# =========================
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

                audited_only = df[(df["status_akhir"].astype(str).str.startswith("✅")) |
                                  (df["status_akhir"].astype(str).str.contains("GUGUR")) |
                                  (df["status_akhir"].astype(str).str.contains("CEK MANUAL"))]

                st.subheader("Ringkasan (HANYA yang diaudit)")
                c1, c2, c3, c4 = st.columns(4)
                c1.metric("Total Diaudit", len(audited_only))
                c2.metric("VALID", int((audited_only["status_akhir"] == "✅ VALID").sum()))
                c3.metric("GUGUR", int(audited_only["status_akhir"].astype(str).str.contains("GUGUR").sum()))
                c4.metric("CEK MANUAL", int(audited_only["status_akhir"].astype(str).str.contains("CEK MANUAL").sum()))

                st.subheader("Laporan (Termasuk SKIP)")
                report = df.drop(columns=["thumb"], errors="ignore")
                st.dataframe(report, use_container_width=True)

                out = io.BytesIO()
                report.to_excel(out, index=False)
                today = datetime.now().strftime("%Y-%m-%d")
                st.download_button(
                    "📥 Download Laporan (Excel)",
                    data=out.getvalue(),
                    file_name=f"Laporan_Audit_Foto_{today}.xlsx",
                    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                )

                st.subheader("Preview (dibatasi)")
                shown = 0
                cols = st.columns(4)

                def prio(s):
                    s = str(s)
                    if "GUGUR" in s or "CEK MANUAL" in s:
                        return 0
                    if s.startswith("✅"):
                        return 1
                    if s.startswith("⏭️ SKIP"):
                        return 2
                    return 3

                df_view = df.copy()
                df_view["_p"] = df_view["status_akhir"].map(prio)
                df_view = df_view.sort_values("_p").drop(columns=["_p"])

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
