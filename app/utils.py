"""Utility umum untuk aplikasi enkripsi dan dekripsi edukatif."""

from __future__ import annotations

import base64
import os
import re
from pathlib import Path
from typing import Iterator, Optional

BLOCK_SIZE = 16
MODES = ("ECB", "CBC", "CTR")
MODE_NEEDS_IV = {"ECB": False, "CBC": True, "CTR": True}


def ensure_mode(mode: str) -> str:
    """Validasi mode operasi dan kembalikan bentuk huruf besar."""
    normalized = (mode or "").strip().upper()
    if normalized not in MODES:
        raise ValueError("Mode harus salah satu dari ECB, CBC, atau CTR.")
    return normalized


def ensure_key_text(key_text: str) -> str:
    """Pastikan user memberikan key yang tidak kosong."""
    if not key_text or not key_text.strip():
        raise ValueError("Key tidak boleh kosong.")
    return key_text


def normalize_user_key(key_text: str) -> bytes:
    """Konversi key dari teks ke bytes UTF-8."""
    return ensure_key_text(key_text).encode("utf-8")


def xor_bytes(left: bytes, right: bytes) -> bytes:
    """XOR dua byte-string dengan panjang yang sama."""
    if len(left) != len(right):
        raise ValueError("Panjang data untuk XOR harus sama.")
    return bytes(a ^ b for a, b in zip(left, right))


def rotate_left(value: int, shift: int, width: int) -> int:
    """Rotasi bit ke kiri."""
    if width <= 0:
        raise ValueError("Lebar rotasi harus lebih besar dari nol.")
    shift %= width
    mask = (1 << width) - 1
    return ((value << shift) & mask) | ((value & mask) >> (width - shift))


def rotate_right(value: int, shift: int, width: int) -> int:
    """Rotasi bit ke kanan."""
    return rotate_left(value, width - (shift % width), width)


def split_blocks(data: bytes, block_size: int = BLOCK_SIZE) -> Iterator[bytes]:
    """Pisahkan data menjadi blok-blok dengan ukuran tetap."""
    if block_size <= 0:
        raise ValueError("Ukuran blok harus lebih besar dari nol.")
    if len(data) % block_size != 0:
        raise ValueError("Panjang data tidak sesuai ukuran blok.")
    for index in range(0, len(data), block_size):
        yield data[index : index + block_size]


def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """Tambahkan padding PKCS#7 secara manual."""
    if block_size <= 0 or block_size >= 256:
        raise ValueError("Ukuran blok PKCS#7 harus di antara 1 sampai 255.")
    padding_length = block_size - (len(data) % block_size)
    if padding_length == 0:
        padding_length = block_size
    return data + bytes([padding_length]) * padding_length


def pkcs7_unpad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """Hapus padding PKCS#7 dengan validasi."""
    if not data or len(data) % block_size != 0:
        raise ValueError("Padding tidak valid: panjang data tidak sesuai.")
    padding_length = data[-1]
    if padding_length < 1 or padding_length > block_size:
        raise ValueError("Padding tidak valid: nilai byte padding salah.")
    padding_bytes = data[-padding_length:]
    if any(byte != padding_length for byte in padding_bytes):
        raise ValueError("Padding tidak valid: pola PKCS#7 tidak cocok.")
    return data[:-padding_length]


def parse_hex_bytes(
    value: str, expected_length: Optional[int] = None, field_name: str = "data hex"
) -> bytes:
    """Ubah string hex menjadi bytes dengan validasi panjang opsional."""
    cleaned = re.sub(r"\s+", "", value or "")
    if cleaned.startswith("0x") or cleaned.startswith("0X"):
        cleaned = cleaned[2:]
    if not cleaned:
        raise ValueError("{0} hex tidak boleh kosong.".format(field_name))
    if len(cleaned) % 2 != 0:
        raise ValueError("{0} hex harus berjumlah genap.".format(field_name))
    try:
        data = bytes.fromhex(cleaned)
    except ValueError as exc:
        raise ValueError("{0} hex mengandung karakter tidak valid.".format(field_name)) from exc
    if expected_length is not None and len(data) != expected_length:
        raise ValueError(
            "{0} harus sepanjang {1} byte ({2} karakter hex).".format(
                field_name, expected_length, expected_length * 2
            )
        )
    return data


def bytes_to_hex(data: bytes) -> str:
    """Representasi hex lowercase."""
    return data.hex()


def hex_to_bytes(value: str) -> bytes:
    """Alias parsing untuk data cipher berbentuk hex."""
    return parse_hex_bytes(value, field_name="ciphertext")


def bytes_to_base64(data: bytes) -> str:
    """Encode bytes ke base64."""
    return base64.b64encode(data).decode("ascii")


def base64_to_bytes(value: str) -> bytes:
    """Decode base64 dengan validasi sederhana."""
    cleaned = "".join((value or "").split())
    if not cleaned:
        raise ValueError("Input base64 tidak boleh kosong.")
    try:
        return base64.b64decode(cleaned.encode("ascii"), validate=True)
    except Exception as exc:  # noqa: BLE001 - ingin pesan error yang ringkas
        raise ValueError("Input base64 tidak valid.") from exc


def generate_random_bytes(length: int) -> bytes:
    """Bangkitkan bytes acak menggunakan standard library."""
    if length <= 0:
        raise ValueError("Panjang data acak harus lebih besar dari nol.")
    return os.urandom(length)


def increment_counter(block: bytes) -> bytes:
    """Naikkan counter CTR sebagai bilangan big-endian."""
    if not block:
        raise ValueError("Counter CTR tidak boleh kosong.")
    value = int.from_bytes(block, "big")
    value = (value + 1) % (1 << (len(block) * 8))
    return value.to_bytes(len(block), "big")


def fnv1a64(data: bytes) -> int:
    """Checksum 64-bit sederhana untuk verifikasi integritas non-kripto."""
    hash_value = 0xCBF29CE484222325
    fnv_prime = 0x100000001B3
    for byte in data:
        hash_value ^= byte
        hash_value = (hash_value * fnv_prime) % (1 << 64)
    return hash_value


def checksum_hex(data: bytes) -> str:
    """Representasi hex checksum 64-bit."""
    return fnv1a64(data).to_bytes(8, "big").hex()


def looks_like_text(data: bytes) -> bool:
    """Deteksi kasar apakah byte kemungkinan besar adalah teks UTF-8."""
    if not data:
        return True
    sample = data[:2048]
    try:
        decoded = sample.decode("utf-8")
    except UnicodeDecodeError:
        return False
    printable = 0
    for char in decoded:
        if char.isprintable() or char in "\r\n\t":
            printable += 1
    return printable / max(1, len(decoded)) >= 0.85


def preview_bytes(data: bytes, max_chars: int = 240) -> str:
    """Preview singkat untuk kebutuhan UI dan CLI."""
    if looks_like_text(data):
        preview = data.decode("utf-8", errors="replace")
        if len(preview) > max_chars:
            return preview[:max_chars] + "..."
        return preview
    preview = data[:64].hex()
    if len(data) > 64:
        return preview + "..."
    return preview


def sanitize_filename(name: str) -> str:
    """Bersihkan nama file agar aman untuk ditulis ke direktori output."""
    candidate = Path(name or "output.bin").name
    candidate = re.sub(r"[^A-Za-z0-9._-]+", "_", candidate).strip("._")
    return candidate or "output.bin"


def ensure_unique_path(directory: Path, filename: str) -> Path:
    """Buat path output unik tanpa menimpa file yang sudah ada."""
    directory.mkdir(parents=True, exist_ok=True)
    base_name = Path(filename).stem
    suffix = Path(filename).suffix
    candidate = directory / filename
    counter = 1
    while candidate.exists():
        candidate = directory / "{0}_{1}{2}".format(base_name, counter, suffix)
        counter += 1
    return candidate


def format_size(num_bytes: int) -> str:
    """Format ukuran byte menjadi bentuk yang mudah dibaca."""
    size = float(num_bytes)
    units = ["B", "KB", "MB", "GB"]
    for unit in units:
        if size < 1024 or unit == units[-1]:
            return "{0:.2f} {1}".format(size, unit)
        size /= 1024
    return "{0:.2f} GB".format(size)

