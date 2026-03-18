"""Payload metadata untuk teks dan file terenkripsi."""

from __future__ import annotations

import base64
import json

from app.utils import bytes_to_base64, ensure_mode, sanitize_filename

TEXT_PAYLOAD_VERSION = 1
FILE_MAGIC = b"EDUPACK1"
FILE_VERSION = 1
MODE_TO_CODE = {"ECB": 1, "CBC": 2, "CTR": 3}
CODE_TO_MODE = {value: key for key, value in MODE_TO_CODE.items()}


def _urlsafe_b64decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode((value + padding).encode("ascii"))


def build_text_payload(
    mode: str,
    iv_or_nonce: bytes,
    ciphertext: bytes,
    checksum: int,
    encoding: str = "utf-8",
) -> str:
    """Bangun payload teks self-contained berbasis JSON + base64."""
    payload = {
        "v": TEXT_PAYLOAD_VERSION,
        "t": "text",
        "m": ensure_mode(mode),
        "iv": iv_or_nonce.hex(),
        "cs": checksum.to_bytes(8, "big").hex(),
        "ct": bytes_to_base64(ciphertext),
        "enc": encoding,
    }
    serialized = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return base64.urlsafe_b64encode(serialized).decode("ascii")


def parse_text_payload(payload_text: str) -> dict:
    """Baca kembali payload teks self-contained."""
    try:
        raw = _urlsafe_b64decode("".join((payload_text or "").split()))
        payload = json.loads(raw.decode("utf-8"))
    except Exception as exc:  # noqa: BLE001 - pesan error dibersihkan untuk user
        raise ValueError("Payload teks tidak valid.") from exc
    if payload.get("v") != TEXT_PAYLOAD_VERSION or payload.get("t") != "text":
        raise ValueError("Versi payload teks tidak didukung.")
    try:
        mode = ensure_mode(payload["m"])
        iv_or_nonce = bytes.fromhex(payload["iv"])
        checksum = int(payload["cs"], 16)
        ciphertext = base64.b64decode(payload["ct"].encode("ascii"), validate=True)
    except Exception as exc:  # noqa: BLE001
        raise ValueError("Isi payload teks tidak lengkap atau rusak.") from exc
    return {
        "mode": mode,
        "iv_or_nonce": iv_or_nonce,
        "checksum": checksum,
        "ciphertext": ciphertext,
        "encoding": payload.get("enc", "utf-8"),
    }


def pack_file_payload(
    mode: str,
    iv_or_nonce: bytes,
    original_name: str,
    original_size: int,
    checksum: int,
    ciphertext: bytes,
) -> bytes:
    """Gabungkan metadata file dan ciphertext ke satu file paket."""
    sanitized_name = sanitize_filename(original_name)
    name_bytes = sanitized_name.encode("utf-8")
    normalized = ensure_mode(mode)
    header = bytearray()
    header.extend(FILE_MAGIC)
    header.append(FILE_VERSION)
    header.append(MODE_TO_CODE[normalized])
    header.append(len(iv_or_nonce))
    header.extend(len(name_bytes).to_bytes(2, "big"))
    header.extend(original_size.to_bytes(8, "big"))
    header.extend(checksum.to_bytes(8, "big"))
    header.extend(name_bytes)
    header.extend(iv_or_nonce)
    header.extend(ciphertext)
    return bytes(header)


def unpack_file_payload(package_bytes: bytes) -> dict:
    """Pisahkan metadata dan ciphertext dari file paket."""
    minimum_header_length = len(FILE_MAGIC) + 1 + 1 + 1 + 2 + 8 + 8
    if len(package_bytes) < minimum_header_length:
        raise ValueError("File terenkripsi terlalu pendek untuk diproses.")
    cursor = 0
    magic = package_bytes[cursor : cursor + len(FILE_MAGIC)]
    cursor += len(FILE_MAGIC)
    if magic != FILE_MAGIC:
        raise ValueError("Format file terenkripsi tidak dikenali.")
    version = package_bytes[cursor]
    cursor += 1
    if version != FILE_VERSION:
        raise ValueError("Versi file terenkripsi tidak didukung.")
    mode_code = package_bytes[cursor]
    cursor += 1
    if mode_code not in CODE_TO_MODE:
        raise ValueError("Kode mode pada file terenkripsi tidak valid.")
    iv_length = package_bytes[cursor]
    cursor += 1
    name_length = int.from_bytes(package_bytes[cursor : cursor + 2], "big")
    cursor += 2
    original_size = int.from_bytes(package_bytes[cursor : cursor + 8], "big")
    cursor += 8
    checksum = int.from_bytes(package_bytes[cursor : cursor + 8], "big")
    cursor += 8
    end_of_name = cursor + name_length
    if end_of_name > len(package_bytes):
        raise ValueError("Metadata nama file pada paket terenkripsi rusak.")
    original_name = package_bytes[cursor:end_of_name].decode("utf-8")
    cursor = end_of_name
    end_of_iv = cursor + iv_length
    if end_of_iv > len(package_bytes):
        raise ValueError("Metadata IV/nonce pada paket terenkripsi rusak.")
    iv_or_nonce = package_bytes[cursor:end_of_iv]
    ciphertext = package_bytes[end_of_iv:]
    return {
        "mode": CODE_TO_MODE[mode_code],
        "iv_or_nonce": iv_or_nonce,
        "original_name": original_name,
        "original_size": original_size,
        "checksum": checksum,
        "ciphertext": ciphertext,
    }

