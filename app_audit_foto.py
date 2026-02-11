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
import math

# =========================
# CONFIG UI
# =========================
st.set_page_config(page_title="Audit Foto Patroli", layout="wide")
st.title("🕵️ AUDIT FOTO PATROLI")
st.caption(
    "Audit foto patroli duplicate (Embedded Excel + Google Docs/Drive). "
    "Foto patroli yang punya overlay GEO (timestamp/koordinat + kotak gelap + teks putih) akan DIAUDIT (VALID/GUGUR). "
    "Logo-only / banner-only akan di-SKIP (tidak masuk VALID/GUGUR)."
)

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
# RESET / HAPUS HISTORY AUDIT
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
# DETEKSI GEO OVERLAY (LEBIH KUAT)
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
    Scan 3 area bawah: kiri-bawah, tengah-bawah, kanan-bawah.
    Overlay GEO bisa muncul di mana saja di bawah (bukan selalu kanan).
    Kriteria: 2 dari 3 -> (white_text, dark_box, contrast).
    """
    w, h = img.size
    if w < 240 or h < 240:
        return False, "SKIP: ukuran kecil"

    # definisi 3 ROI bawah
    rois = [
        ("LB", (0.00, 0.65, 0.45, 1.00)),   # left-bottom
        ("MB", (0.25, 0.65, 0.75, 1.00)),   # mid-bottom
        ("RB", (0.55, 0.65, 1.00, 1.00)),   # right-bottom
    ]

    best = None
    best_dbg = ""

    for name, (x0, y0, x1, y1) in rois:
        X0 = int(w * x0); Y0 = int(h * y0)
        X1 = int(w * x1); Y1 = int(h * y1)

        patch = img.crop((X0, Y0, X1, Y1)).convert("L").resize((240, 240))
        mean, std, white_ratio, dark_ratio = _patch_stats(patch)

        # threshold dibuat longgar (teks tipis pun lolos)
        has_white_text = white_ratio >= 0.004   # 0.4%
        has_dark_box   = dark_ratio  >= 0.008   # 0.8%
        has_contrast   = std >= 16              # sedikit lebih longgar

        score = int(has_white_text) + int(has_dark_box) + int(has_contrast)
        dbg = f"{name}: mean={mean:.1f}, std={std:.1f}, white={white_ratio:.3f}, dark={dark_ratio:.3f}, score={score}"

        if best is None or score > best:
            best = score
            best_dbg = dbg

    if best is not None and best >= 2:
        return True, f"GEO overlay terdeteksi ✅ ({best_dbg})"

    return False, f"Non-GEO ({best_dbg})"

def classify_for_audit(img: Image.Image) -> tuple[bool, str, str]:
    """
    RULE FINAL (sesuai kemauan kamu):
    - Ada GEO overlay -> MASUK AUDIT (logo perusahaan boleh ada)
    - Tidak ada GEO overlay -> SKIP (logo-only / banner-only / non patroli)
    """
    ok, why = overlay_geo_best(img)
    if ok:
        return
