"""Implementasi mode operasi block cipher secara manual."""

from __future__ import annotations

from typing import Optional

from app.cipher import AcademicBlockCipher
from app.utils import BLOCK_SIZE, ensure_mode, increment_counter, pkcs7_pad, pkcs7_unpad, split_blocks, xor_bytes


def _validate_iv(mode: str, iv_or_nonce: Optional[bytes]) -> bytes:
    """Pastikan IV/nonce sesuai kebutuhan mode operasi."""
    normalized = ensure_mode(mode)
    if normalized == "ECB":
        return b""
    if iv_or_nonce is None or len(iv_or_nonce) != BLOCK_SIZE:
        raise ValueError("Mode {0} membutuhkan IV/nonce sepanjang 16 byte.".format(normalized))
    return iv_or_nonce


def _encrypt_ecb(cipher: AcademicBlockCipher, plaintext: bytes) -> bytes:
    padded = pkcs7_pad(plaintext, cipher.BLOCK_SIZE)
    return b"".join(cipher.encrypt_block(block) for block in split_blocks(padded, cipher.BLOCK_SIZE))


def _decrypt_ecb(cipher: AcademicBlockCipher, ciphertext: bytes) -> bytes:
    if len(ciphertext) % cipher.BLOCK_SIZE != 0:
        raise ValueError("Ciphertext ECB harus kelipatan ukuran blok.")
    padded = b"".join(cipher.decrypt_block(block) for block in split_blocks(ciphertext, cipher.BLOCK_SIZE))
    return pkcs7_unpad(padded, cipher.BLOCK_SIZE)


def _encrypt_cbc(cipher: AcademicBlockCipher, plaintext: bytes, iv: bytes) -> bytes:
    padded = pkcs7_pad(plaintext, cipher.BLOCK_SIZE)
    previous = iv
    blocks = []
    for block in split_blocks(padded, cipher.BLOCK_SIZE):
        mixed = xor_bytes(block, previous)
        encrypted = cipher.encrypt_block(mixed)
        blocks.append(encrypted)
        previous = encrypted
    return b"".join(blocks)


def _decrypt_cbc(cipher: AcademicBlockCipher, ciphertext: bytes, iv: bytes) -> bytes:
    if len(ciphertext) % cipher.BLOCK_SIZE != 0:
        raise ValueError("Ciphertext CBC harus kelipatan ukuran blok.")
    previous = iv
    blocks = []
    for block in split_blocks(ciphertext, cipher.BLOCK_SIZE):
        decrypted = cipher.decrypt_block(block)
        blocks.append(xor_bytes(decrypted, previous))
        previous = block
    return pkcs7_unpad(b"".join(blocks), cipher.BLOCK_SIZE)


def _apply_ctr(cipher: AcademicBlockCipher, data: bytes, nonce: bytes) -> bytes:
    counter = nonce
    output = bytearray()
    for index in range(0, len(data), cipher.BLOCK_SIZE):
        block = data[index : index + cipher.BLOCK_SIZE]
        keystream = cipher.encrypt_block(counter)
        output.extend(xor_bytes(block, keystream[: len(block)]))
        counter = increment_counter(counter)
    return bytes(output)


def encrypt_bytes(
    cipher: AcademicBlockCipher,
    plaintext: bytes,
    mode: str,
    iv_or_nonce: Optional[bytes] = None,
) -> bytes:
    """Enkripsi data arbitrer sesuai mode operasi."""
    normalized = ensure_mode(mode)
    iv_value = _validate_iv(normalized, iv_or_nonce)
    if normalized == "ECB":
        return _encrypt_ecb(cipher, plaintext)
    if normalized == "CBC":
        return _encrypt_cbc(cipher, plaintext, iv_value)
    return _apply_ctr(cipher, plaintext, iv_value)


def decrypt_bytes(
    cipher: AcademicBlockCipher,
    ciphertext: bytes,
    mode: str,
    iv_or_nonce: Optional[bytes] = None,
) -> bytes:
    """Dekripsi data arbitrer sesuai mode operasi."""
    normalized = ensure_mode(mode)
    iv_value = _validate_iv(normalized, iv_or_nonce)
    if normalized == "ECB":
        return _decrypt_ecb(cipher, ciphertext)
    if normalized == "CBC":
        return _decrypt_cbc(cipher, ciphertext, iv_value)
    return _apply_ctr(cipher, ciphertext, iv_value)

