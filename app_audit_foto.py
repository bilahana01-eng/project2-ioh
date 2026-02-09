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
st.caption("Mendeteksi foto yang sama walau rename / repost lintas bulan. Support foto embedded Excel + Google Docs/Drive link.")

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
