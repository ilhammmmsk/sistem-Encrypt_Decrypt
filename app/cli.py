"""CLI fallback untuk aplikasi penyandian data digital."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Optional, Sequence

from app.service import (
    DEFAULT_OUTPUT_DIR,
    decrypt_file_from_path,
    decrypt_text,
    encrypt_file_from_path,
    encrypt_text,
)
from app.webapp import run_server


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Aplikasi enkripsi/dekripsi edukatif berbasis block cipher buatan sendiri."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    web_parser = subparsers.add_parser("web", help="Jalankan Web UI.")
    web_parser.add_argument("--host", default="127.0.0.1", help="Host server Web UI.")
    web_parser.add_argument("--port", type=int, default=8000, help="Port server Web UI.")

    text_encrypt = subparsers.add_parser("text-encrypt", help="Enkripsi teks.")
    text_encrypt.add_argument("--mode", required=True, choices=["ECB", "CBC", "CTR"])
    text_encrypt.add_argument("--key", required=True, help="Key dari user.")
    text_encrypt.add_argument("--text", required=True, help="Teks yang ingin dienkripsi.")
    text_encrypt.add_argument("--iv", default="", help="IV/nonce hex 16 byte. Kosongkan untuk auto-generate.")

    text_decrypt = subparsers.add_parser("text-decrypt", help="Dekripsi teks.")
    text_decrypt.add_argument("--key", required=True, help="Key dari user.")
    text_decrypt.add_argument("--input", required=True, help="Ciphertext atau payload.")
    text_decrypt.add_argument(
        "--input-format",
        default="payload",
        choices=["payload", "hex", "base64"],
        help="Format input dekripsi teks.",
    )
    text_decrypt.add_argument("--mode", choices=["ECB", "CBC", "CTR"], help="Mode jika input bukan payload.")
    text_decrypt.add_argument("--iv", default="", help="IV/nonce hex 16 byte jika input bukan payload.")

    file_encrypt = subparsers.add_parser("file-encrypt", help="Enkripsi file.")
    file_encrypt.add_argument("--mode", required=True, choices=["ECB", "CBC", "CTR"])
    file_encrypt.add_argument("--key", required=True, help="Key dari user.")
    file_encrypt.add_argument("--input", required=True, help="Path file sumber.")
    file_encrypt.add_argument("--iv", default="", help="IV/nonce hex 16 byte. Kosongkan untuk auto-generate.")
    file_encrypt.add_argument(
        "--output-dir",
        default=str(DEFAULT_OUTPUT_DIR),
        help="Direktori hasil file terenkripsi.",
    )

    file_decrypt = subparsers.add_parser("file-decrypt", help="Dekripsi file paket terenkripsi.")
    file_decrypt.add_argument("--key", required=True, help="Key dari user.")
    file_decrypt.add_argument("--input", required=True, help="Path file paket terenkripsi.")
    file_decrypt.add_argument(
        "--output-dir",
        default=str(DEFAULT_OUTPUT_DIR),
        help="Direktori hasil file dekripsi.",
    )

    return parser


def _print_kv(title: str, value: object) -> None:
    print("{0:<18}: {1}".format(title, value))


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Entry point CLI."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "web":
            run_server(args.host, args.port)
            return 0

        if args.command == "text-encrypt":
            result = encrypt_text(args.text, args.key, args.mode, args.iv)
            _print_kv("Mode", result["mode"])
            _print_kv("IV/Nonce", result["iv_hex"])
            _print_kv("Ukuran input", "{0} byte".format(result["input_size"]))
            _print_kv("Ukuran output", "{0} byte".format(result["output_size"]))
            _print_kv("Cipher Hex", result["ciphertext_hex"])
            _print_kv("Cipher Base64", result["ciphertext_base64"])
            _print_kv("Payload", result["payload"])
            return 0

        if args.command == "text-decrypt":
            result = decrypt_text(
                args.input,
                args.key,
                input_format=args.input_format,
                mode=args.mode,
                iv_hex=args.iv,
            )
            _print_kv("Mode", result["mode"])
            _print_kv("IV/Nonce", result["iv_hex"])
            _print_kv("Ukuran input", "{0} byte".format(result["input_size"]))
            _print_kv("Ukuran output", "{0} byte".format(result["output_size"]))
            _print_kv("Plaintext", result["plaintext"])
            return 0

        if args.command == "file-encrypt":
            result = encrypt_file_from_path(
                args.input,
                args.key,
                args.mode,
                iv_hex=args.iv,
                output_dir=Path(args.output_dir),
            )
            _print_kv("Mode", result["mode"])
            _print_kv("IV/Nonce", result["iv_hex"])
            _print_kv("File sumber", result["original_name"])
            _print_kv("Ukuran input", result["input_size_readable"])
            _print_kv("Ukuran output", result["output_size_readable"])
            _print_kv("Hasil", result["output_path"])
            _print_kv("Preview", result["preview"])
            return 0

        if args.command == "file-decrypt":
            result = decrypt_file_from_path(
                args.input,
                args.key,
                output_dir=Path(args.output_dir),
            )
            _print_kv("Mode", result["mode"])
            _print_kv("IV/Nonce", result["iv_hex"])
            _print_kv("Nama asli", result["original_name"])
            _print_kv("Ukuran output", result["output_size_readable"])
            _print_kv("Hasil", result["output_path"])
            _print_kv("Preview", result["preview"])
            return 0
    except Exception as exc:  # noqa: BLE001 - CLI harus menampilkan error ringkas
        parser.exit(1, "Error: {0}\n".format(exc))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

