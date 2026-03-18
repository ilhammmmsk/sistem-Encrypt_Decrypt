"""Service layer yang menghubungkan cipher, mode, payload, CLI, dan Web UI."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from app.cipher import AcademicBlockCipher
from app.modes import decrypt_bytes, encrypt_bytes
from app.payload import build_text_payload, pack_file_payload, parse_text_payload, unpack_file_payload
from app.utils import (
    BLOCK_SIZE,
    base64_to_bytes,
    bytes_to_base64,
    bytes_to_hex,
    checksum_hex,
    ensure_key_text,
    ensure_mode,
    ensure_unique_path,
    fnv1a64,
    format_size,
    generate_random_bytes,
    hex_to_bytes,
    looks_like_text,
    normalize_user_key,
    parse_hex_bytes,
    preview_bytes,
    sanitize_filename,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "outputs"


def _resolve_iv_for_encrypt(mode: str, iv_hex: str) -> bytes:
    """IV/nonce untuk proses enkripsi: manual jika ada, selain itu acak."""
    normalized = ensure_mode(mode)
    if normalized == "ECB":
        return b""
    if iv_hex and iv_hex.strip():
        return parse_hex_bytes(iv_hex, BLOCK_SIZE, "IV/nonce")
    return generate_random_bytes(BLOCK_SIZE)


def _resolve_iv_for_decrypt(mode: str, iv_hex: str) -> bytes:
    """IV/nonce untuk proses dekripsi: wajib ada pada mode yang memerlukannya."""
    normalized = ensure_mode(mode)
    if normalized == "ECB":
        return b""
    if not iv_hex or not iv_hex.strip():
        raise ValueError("Mode {0} membutuhkan IV/nonce hex 16 byte.".format(normalized))
    return parse_hex_bytes(iv_hex, BLOCK_SIZE, "IV/nonce")


def _parse_cipher_input(cipher_input: str, input_format: str) -> bytes:
    """Ambil bytes ciphertext dari representasi hex atau base64."""
    normalized = (input_format or "").strip().lower()
    if normalized == "hex":
        return hex_to_bytes(cipher_input)
    if normalized == "base64":
        return base64_to_bytes(cipher_input)
    raise ValueError("Format input ciphertext harus hex, base64, atau payload.")


def encrypt_text(
    plain_text: str,
    key_text: str,
    mode: str,
    iv_hex: str = "",
    encoding: str = "utf-8",
) -> dict:
    """Enkripsi teks dan kembalikan hasil siap tampil."""
    ensure_key_text(key_text)
    normalized_mode = ensure_mode(mode)
    plaintext_bytes = (plain_text or "").encode(encoding)
    key_bytes = normalize_user_key(key_text)
    cipher = AcademicBlockCipher(key_bytes)
    iv_or_nonce = _resolve_iv_for_encrypt(normalized_mode, iv_hex)
    ciphertext = encrypt_bytes(cipher, plaintext_bytes, normalized_mode, iv_or_nonce)
    checksum = fnv1a64(plaintext_bytes)
    return {
        "mode": normalized_mode,
        "iv_hex": iv_or_nonce.hex() if iv_or_nonce else "-",
        "ciphertext_hex": bytes_to_hex(ciphertext),
        "ciphertext_base64": bytes_to_base64(ciphertext),
        "payload": build_text_payload(normalized_mode, iv_or_nonce, ciphertext, checksum, encoding),
        "checksum": checksum.to_bytes(8, "big").hex(),
        "input_size": len(plaintext_bytes),
        "output_size": len(ciphertext),
        "input_preview": preview_bytes(plaintext_bytes),
    }


def decrypt_text(
    cipher_input: str,
    key_text: str,
    input_format: str = "payload",
    mode: Optional[str] = None,
    iv_hex: str = "",
) -> dict:
    """Dekripsi teks dari payload, hex, atau base64."""
    ensure_key_text(key_text)
    key_bytes = normalize_user_key(key_text)
    cipher = AcademicBlockCipher(key_bytes)
    format_name = (input_format or "").strip().lower()
    expected_checksum = None
    encoding = "utf-8"
    if format_name == "payload":
        parsed = parse_text_payload(cipher_input)
        normalized_mode = parsed["mode"]
        iv_or_nonce = parsed["iv_or_nonce"]
        ciphertext = parsed["ciphertext"]
        expected_checksum = parsed["checksum"]
        encoding = parsed["encoding"]
    else:
        if mode is None:
            raise ValueError("Mode wajib diisi jika input format bukan payload.")
        normalized_mode = ensure_mode(mode)
        iv_or_nonce = _resolve_iv_for_decrypt(normalized_mode, iv_hex)
        ciphertext = _parse_cipher_input(cipher_input, format_name)
    plaintext_bytes = decrypt_bytes(cipher, ciphertext, normalized_mode, iv_or_nonce)
    if expected_checksum is not None and fnv1a64(plaintext_bytes) != expected_checksum:
        raise ValueError("Kunci salah atau payload teks sudah rusak.")
    try:
        plaintext = plaintext_bytes.decode(encoding)
    except UnicodeDecodeError as exc:
        raise ValueError("Hasil dekripsi tidak dapat dibaca sebagai teks UTF-8.") from exc
    return {
        "mode": normalized_mode,
        "iv_hex": iv_or_nonce.hex() if iv_or_nonce else "-",
        "plaintext": plaintext,
        "checksum": checksum_hex(plaintext_bytes),
        "input_size": len(ciphertext),
        "output_size": len(plaintext_bytes),
        "output_preview": preview_bytes(plaintext_bytes),
    }


def encrypt_file_bytes(
    file_bytes: bytes,
    original_name: str,
    key_text: str,
    mode: str,
    iv_hex: str = "",
    output_dir: Path = DEFAULT_OUTPUT_DIR,
) -> dict:
    """Enkripsi bytes file lalu simpan sebagai paket file terenkripsi."""
    ensure_key_text(key_text)
    normalized_mode = ensure_mode(mode)
    safe_name = sanitize_filename(original_name)
    key_bytes = normalize_user_key(key_text)
    cipher = AcademicBlockCipher(key_bytes)
    iv_or_nonce = _resolve_iv_for_encrypt(normalized_mode, iv_hex)
    ciphertext = encrypt_bytes(cipher, file_bytes, normalized_mode, iv_or_nonce)
    checksum = fnv1a64(file_bytes)
    package = pack_file_payload(
        normalized_mode,
        iv_or_nonce,
        safe_name,
        len(file_bytes),
        checksum,
        ciphertext,
    )
    output_path = ensure_unique_path(Path(output_dir), safe_name + ".edc")
    output_path.write_bytes(package)
    return {
        "mode": normalized_mode,
        "iv_hex": iv_or_nonce.hex() if iv_or_nonce else "-",
        "original_name": safe_name,
        "output_path": str(output_path),
        "output_name": output_path.name,
        "input_size": len(file_bytes),
        "output_size": len(package),
        "input_size_readable": format_size(len(file_bytes)),
        "output_size_readable": format_size(len(package)),
        "is_text": looks_like_text(file_bytes),
        "preview": preview_bytes(file_bytes),
        "checksum": checksum.to_bytes(8, "big").hex(),
    }


def decrypt_file_bytes(
    package_bytes: bytes,
    key_text: str,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
) -> dict:
    """Dekripsi paket file terenkripsi lalu tulis kembali file aslinya."""
    ensure_key_text(key_text)
    package = unpack_file_payload(package_bytes)
    key_bytes = normalize_user_key(key_text)
    cipher = AcademicBlockCipher(key_bytes)
    plaintext = decrypt_bytes(
        cipher,
        package["ciphertext"],
        package["mode"],
        package["iv_or_nonce"],
    )
    if len(plaintext) != package["original_size"]:
        raise ValueError("Ukuran hasil dekripsi tidak cocok. Kunci salah atau data rusak.")
    if fnv1a64(plaintext) != package["checksum"]:
        raise ValueError("Checksum tidak cocok. Kunci salah atau data rusak.")
    output_name = "decrypted_" + sanitize_filename(package["original_name"])
    output_path = ensure_unique_path(Path(output_dir), output_name)
    output_path.write_bytes(plaintext)
    return {
        "mode": package["mode"],
        "iv_hex": package["iv_or_nonce"].hex() if package["iv_or_nonce"] else "-",
        "original_name": package["original_name"],
        "output_path": str(output_path),
        "output_name": output_path.name,
        "input_size": len(package_bytes),
        "output_size": len(plaintext),
        "input_size_readable": format_size(len(package_bytes)),
        "output_size_readable": format_size(len(plaintext)),
        "is_text": looks_like_text(plaintext),
        "preview": preview_bytes(plaintext),
        "checksum": checksum_hex(plaintext),
    }


def encrypt_file_from_path(
    input_path: str,
    key_text: str,
    mode: str,
    iv_hex: str = "",
    output_dir: Path = DEFAULT_OUTPUT_DIR,
) -> dict:
    """Wrapper CLI untuk file sumber dari path disk."""
    source_path = Path(input_path)
    if not source_path.is_file():
        raise ValueError("File input tidak ditemukan: {0}".format(source_path))
    return encrypt_file_bytes(
        source_path.read_bytes(),
        source_path.name,
        key_text,
        mode,
        iv_hex=iv_hex,
        output_dir=output_dir,
    )


def decrypt_file_from_path(
    input_path: str,
    key_text: str,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
) -> dict:
    """Wrapper CLI untuk paket file terenkripsi dari path disk."""
    source_path = Path(input_path)
    if not source_path.is_file():
        raise ValueError("File terenkripsi tidak ditemukan: {0}".format(source_path))
    return decrypt_file_bytes(source_path.read_bytes(), key_text, output_dir=output_dir)

