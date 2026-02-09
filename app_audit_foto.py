import streamlit as st
import pandas as pd
from openpyxl import load_workbook
from PIL import Image, UnidentifiedImageError
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

# =========================
# CONFIG UI
# =========================
st.set_page_config(page_title="Audit Foto Patroli", layout="wide")
st.title("🕵️ AUDIT FOTO PATROLI (Anti Duplikat + Anti Rename)")
st.caption("Mendeteksi foto yang sama walau rename / repost lintas bulan. Support foto embedded Excel + Google Docs/Drive link.")

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
    """
    Return match info:
    - exact match by sha256 (strong)
    - near match by phash (optional / weaker; we will treat equal phash as suspicious)
    """
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
    # store by sha256 primary key, ignore duplicates
    conn.execute("""
        INSERT OR IGNORE INTO history
        (sha256, phash, source_type, source_file, sheet, location, cluster, segment, url, first_seen)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        row["sha256"], row["phash"], row["source_type"], row["source_file"],
        row["sheet"], row["location"], row["cluster"], row["segment"], row["url"], row["first_seen"]
    ))

# =========================
# HELPERS: HASHING
# =========================
def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def compute_hashes_from_bytes(img_bytes: bytes):
    """
    Returns:
      sha256_hex, phash_str, thumbnail(PIL Image or None)
    """
    try:
        img = Image.open(io.BytesIO(img_bytes)).convert("RGB")
    except UnidentifiedImageError:
        return None, None, None

    # thumbnail for preview
    thumb = img.copy()
    thumb.thumbnail((220, 220))

    # perceptual hash computed on resized image for speed
    ph = str(imagehash.phash(thumb))

    # exact hash from bytes
    sh = sha256_bytes(img_bytes)
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

def http_get_bytes(session: requests.Session, url: str, timeout=20) -> bytes | None:
    try:
        r = session.get(url, timeout=timeout, stream=True, allow_redirects=True)
        if r.status_code != 200:
            return None
        return r.content
    except requests.RequestException:
        return None

def extract_images_from_docx_bytes(docx_bytes: bytes) -> list[bytes]:
    """
    DOCX = zip. Images stored under word/media/*
    """
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
    """
    Return list of image bytes from:
    - Google Docs: export docx -> extract word/media images
    - Google Drive file: download -> if image => [bytes]
    Otherwise empty.
    """
    if not url or not isinstance(url, str):
        return []

    # Google Docs document link
    m = DOC_ID_RE.search(url)
    if m:
        doc_id = m.group(1)
        docx_url = build_gdocs_export_docx_url(doc_id)
        docx_bytes = http_get_bytes(session, docx_url)
        if not docx_bytes:
            return []
        return extract_images_from_docx_bytes(docx_bytes)

    # Google Drive file link
    m = DRIVE_FILE_ID_RE.search(url)
    if m:
        file_id = m.group(1)
        b = http_get_bytes(session, build_drive_download_url(file_id))
        return [b] if b else []

    # Generic id=...
    m = GENERIC_ID_RE.search(url)
    if m and "google" in url:
        file_id = m.group(1)
        b = http_get_bytes(session, build_drive_download_url(file_id))
        return [b] if b else []

    return []

# =========================
# EXCEL PARSING
# =========================
def find_header_row_and_cols(ws, max_scan_rows=40):
    """
    Try detect header row by finding cells containing expected header labels.
    Return (header_row, col_cluster, col_segment, col_link)
    If not found, fallback to common (cluster=2, segment=3, link=7, header=4)
    """
    target = {
        "cluster": ["cluster"],
        "segment": ["segment", "segment name", "segmen"],
        "link": ["link", "url"]
    }

    def norm(v):
        return str(v).strip().lower() if v is not None else ""

    for r in range(1, min(max_scan_rows, ws.max_row) + 1):
        row_vals = [norm(ws.cell(r, c).value) for c in range(1, min(ws.max_column, 30) + 1)]
        if not any(row_vals):
            continue

        col_cluster = col_segment = col_link = None
        for idx, val in enumerate(row_vals, start=1):
            if any(k in val for k in target["cluster"]):
                col_cluster = idx
            if any(k in val for k in target["segment"]):
                col_segment = idx
            if any(k in val for k in target["link"]):
                col_link = idx

        if col_cluster and col_segment and col_link:
            return r, col_cluster, col_segment, col_link

    return 4, 2, 3, 7  # fallback

def extract_embedded_images(wb, source_file_name: str):
    items = []
    for ws in wb.worksheets:
        imgs = getattr(ws, "_images", [])
        if not imgs:
            continue

        # detect header layout for metadata row mapping
        header_row, col_cluster, col_segment, col_link = find_header_row_and_cols(ws)

        for img_obj in imgs:
            try:
                # anchor position
                row = img_obj.anchor._from.row + 1
                col = img_obj.anchor._from.col + 1

                # metadata: read from row where image sits
                cluster = ws.cell(row=row, column=col_cluster).value or "N/A"
                segment = ws.cell(row=row, column=col_segment).value or "N/A"

                # bytes from openpyxl image
                img_bytes = img_obj._data()
                sh, ph, thumb = compute_hashes_from_bytes(img_bytes)
                if not sh:
                    continue

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
                    "thumb": thumb
                })
            except:
                continue
    return items

def extract_link_images(wb, source_file_name: str, max_workers=12):
    items = []

    # prepare all url jobs first (so we can run threads)
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
    session.headers.update({"User-Agent": "Mozilla/5.0 (AuditFotoBot)"})

    def worker(job):
        sheet, r, col_link, cluster, segment, url = job
        img_bytes_list = download_images_from_url(session, url)
        out = []
        for idx, b in enumerate(img_bytes_list, start=1):
            if not b:
                continue
            sh, ph, thumb = compute_hashes_from_bytes(b)
            if not sh:
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
def audit_workbook(xlsx_path: str, show_progress=True):
    wb = load_workbook(xlsx_path, data_only=True)
    source_file_name = os.path.basename(xlsx_path)

    embedded = extract_embedded_images(wb, source_file_name)
    linked = extract_link_images(wb, source_file_name)

    all_items = embedded + linked
    df = pd.DataFrame(all_items)
    if df.empty:
        return df

    # Internal duplicates: exact by sha256
    df["dup_internal_exact"] = df.duplicated("sha256", keep="first")

    # Internal duplicates: same phash (more lenient)
    df["dup_internal_phash"] = df.duplicated("phash", keep="first")

    conn = get_db()
    first_seen = datetime.now().strftime("%Y-%m-%d")
    df["first_seen"] = first_seen

    # History lookup
    hist_status = []
    hist_detail = []
    for _, row in df.iterrows():
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
    df["history_status"] = hist_status
    df["history_detail"] = hist_detail

    # Final decision
    def decide(r):
        # paling keras: pernah terbit exact
        if r["history_status"] == "REUPLOAD_EXACT":
            return "❌ GUGUR (Pernah Terbit - Exact)"
        # phash match: indikasi reuse walau edit/kompres
        if r["history_status"] == "REUPLOAD_SIMILAR_PHASH":
            return "⚠️ CEK MANUAL (Mirip Foto Lama)"
        # duplikat internal exact
        if r["dup_internal_exact"]:
            return "❌ GUGUR (Duplikat di File Ini - Exact)"
        # duplikat internal phash (lebih longgar)
        if r["dup_internal_phash"]:
            return "⚠️ CEK MANUAL (Duplikat Mirip di File Ini)"
        return "✅ VALID"

    df["status_akhir"] = df.apply(decide, axis=1)

    # Insert VALID to DB (atau kamu bisa pilih insert juga yang "cek manual")
    for _, r in df[df["status_akhir"] == "✅ VALID"].iterrows():
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

    return df

# =========================
# STREAMLIT UI
# =========================
uploaded = st.file_uploader("Upload Excel Patroli (.xlsx)", type=["xlsx"])

colA, colB = st.columns([1, 2])
with colA:
    preview_limit = st.number_input("Maks preview gambar", min_value=0, max_value=300, value=60, step=10)
with colB:
    st.info("Catatan: Link Google Docs akan di-export DOCX lalu diambil semua gambar di dalamnya (word/media).")

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

                # Summary
                st.subheader("Ringkasan")
                c1, c2, c3, c4 = st.columns(4)
                c1.metric("Total Foto Terdeteksi", len(df))
                c2.metric("VALID", int((df["status_akhir"] == "✅ VALID").sum()))
                c3.metric("GUGUR", int(df["status_akhir"].str.contains("GUGUR").sum()))
                c4.metric("CEK MANUAL", int(df["status_akhir"].str.contains("CEK MANUAL").sum()))

                # Report
                st.subheader("Laporan")
                report = df.drop(columns=["thumb"])  # jangan taruh thumbnail di excel
                st.dataframe(report, use_container_width=True)

                # Download report excel
                out = io.BytesIO()
                report.to_excel(out, index=False)
                today = datetime.now().strftime("%Y-%m-%d")
                st.download_button(
                    "📥 Download Laporan (Excel)",
                    data=out.getvalue(),
                    file_name=f"Laporan_Audit_Foto_{today}.xlsx",
                    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                )

                # Preview (only limited)
                st.subheader("Preview Foto (dibatasi)")
                shown = 0
                cols = st.columns(4)
                for i, r in df.iterrows():
                    if preview_limit == 0:
                        break
                    if shown >= preview_limit:
                        break
                    if r["thumb"] is None:
                        continue

                    # untuk hemat, prioritaskan yang bermasalah
                    if r["status_akhir"] == "✅ VALID" and shown > (preview_limit // 2):
                        continue

                    with cols[shown % 4]:
                        st.image(
                            r["thumb"],
                            caption=f'{r["sheet"]} | {r["location"]}\n{r["status_akhir"]}'
                        )
                        if r["history_detail"]:
                            st.caption(r["history_detail"])
                    shown += 1

    if os.path.exists(tmp_path):
        os.remove(tmp_path)

st.divider()
st.caption(f"DB history disimpan lokal: {DB_PATH} (jangan dihapus kalau mau deteksi lintas bulan)")
