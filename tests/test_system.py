"""Pengujian dasar untuk aplikasi Edu Cipher Lab."""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from app.cipher import AcademicBlockCipher
from app.modes import decrypt_bytes, encrypt_bytes
from app.service import decrypt_file_bytes, decrypt_text, encrypt_file_bytes, encrypt_text
from app.utils import BLOCK_SIZE, normalize_user_key


class EduCipherSystemTests(unittest.TestCase):
    """Uji round-trip teks, file, dan mode operasi."""

    def test_text_roundtrip_all_modes(self) -> None:
        plaintext = "Halo dunia. Ini teks uji untuk tugas kriptografi."
        key = "KunciAkademik123"
        for mode in ("ECB", "CBC", "CTR"):
            encrypted = encrypt_text(plaintext, key, mode)
            decrypted = decrypt_text(encrypted["payload"], key, input_format="payload")
            self.assertEqual(plaintext, decrypted["plaintext"])

    def test_mode_roundtrip_raw_bytes(self) -> None:
        key_bytes = normalize_user_key("ModeTestKey")
        cipher = AcademicBlockCipher(key_bytes)
        raw_data = (b"ABCDEFGHIJKLMNOP" * 4) + b"akhir"
        iv = bytes(range(BLOCK_SIZE))
        for mode in ("ECB", "CBC", "CTR"):
            encrypted = encrypt_bytes(cipher, raw_data, mode, iv if mode != "ECB" else b"")
            decrypted = decrypt_bytes(cipher, encrypted, mode, iv if mode != "ECB" else b"")
            self.assertEqual(raw_data, decrypted)

    def test_text_file_roundtrip(self) -> None:
        with TemporaryDirectory() as tmp_dir:
            original = "Ini adalah contoh file teks untuk pengujian.".encode("utf-8")
            encrypted = encrypt_file_bytes(
                original,
                "catatan_uji.txt",
                "FileTextKey!",
                "CBC",
                output_dir=Path(tmp_dir),
            )
            package_bytes = Path(encrypted["output_path"]).read_bytes()
            decrypted = decrypt_file_bytes(package_bytes, "FileTextKey!", output_dir=Path(tmp_dir))
            self.assertEqual(original, Path(decrypted["output_path"]).read_bytes())

    def test_binary_file_roundtrip(self) -> None:
        with TemporaryDirectory() as tmp_dir:
            original = bytes(range(256)) + b"\x00\x01\x02\x03" + bytes(reversed(range(256)))
            encrypted = encrypt_file_bytes(
                original,
                "sample.bin",
                "BinaryFileKey!",
                "CTR",
                output_dir=Path(tmp_dir),
            )
            package_bytes = Path(encrypted["output_path"]).read_bytes()
            decrypted = decrypt_file_bytes(package_bytes, "BinaryFileKey!", output_dir=Path(tmp_dir))
            self.assertEqual(original, Path(decrypted["output_path"]).read_bytes())

    def test_wrong_key_detected_by_payload_checksum(self) -> None:
        encrypted = encrypt_text("Pesan rahasia akademik", "KunciBenar", "CTR")
        with self.assertRaises(ValueError):
            decrypt_text(encrypted["payload"], "KunciSalah", input_format="payload")


if __name__ == "__main__":
    unittest.main()

