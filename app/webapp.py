"""Web UI sederhana berbasis http.server tanpa dependensi eksternal."""

from __future__ import annotations

import argparse
import mimetypes
from dataclasses import dataclass
from email.parser import BytesParser
from email.policy import default
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, Optional, Sequence
from urllib.parse import parse_qs, quote, unquote

from app.service import DEFAULT_OUTPUT_DIR, decrypt_file_bytes, decrypt_text, encrypt_file_bytes, encrypt_text

PROJECT_ROOT = Path(__file__).resolve().parent.parent
STATIC_DIR = Path(__file__).resolve().parent / "static"


@dataclass
class UploadedFile:
    """Representasi sederhana file upload dari form multipart."""

    filename: str
    content: bytes


class ParsedForm:
    """Abstraksi kecil pengganti kebutuhan dasar dari cgi.FieldStorage."""

    def __init__(
        self,
        fields: Optional[Dict[str, Sequence[str]]] = None,
        files: Optional[Dict[str, UploadedFile]] = None,
    ) -> None:
        self._fields = {key: list(values) for key, values in (fields or {}).items()}
        self._files = files or {}

    def getfirst(self, name: str, default_value: str = "") -> str:
        values = self._fields.get(name)
        if not values:
            return default_value
        return values[0]

    def getfile(self, name: str) -> Optional[UploadedFile]:
        return self._files.get(name)


def _decode_text_field(payload: bytes, charset: Optional[str]) -> str:
    """Decode field form menjadi string dengan fallback aman."""
    encoding = charset or "utf-8"
    return payload.decode(encoding, errors="replace")


def parse_http_form(content_type: str, body: bytes) -> ParsedForm:
    """Parse body POST x-www-form-urlencoded atau multipart/form-data."""
    normalized = (content_type or "").split(";", 1)[0].strip().lower()
    if normalized == "application/x-www-form-urlencoded":
        parsed = parse_qs(body.decode("utf-8", errors="replace"), keep_blank_values=True)
        return ParsedForm(fields=parsed)

    if normalized == "multipart/form-data":
        headers = "Content-Type: {0}\r\nMIME-Version: 1.0\r\n\r\n".format(content_type).encode("utf-8")
        message = BytesParser(policy=default).parsebytes(headers + body)
        if not message.is_multipart():
            raise ValueError("Body multipart/form-data tidak valid.")
        fields: Dict[str, list[str]] = {}
        files: Dict[str, UploadedFile] = {}
        for part in message.iter_parts():
            if part.get_content_disposition() != "form-data":
                continue
            field_name = part.get_param("name", header="content-disposition")
            if not field_name:
                continue
            payload = part.get_payload(decode=True) or b""
            filename = part.get_filename()
            if filename is None:
                fields.setdefault(field_name, []).append(
                    _decode_text_field(payload, part.get_content_charset())
                )
                continue
            files[field_name] = UploadedFile(filename=filename, content=payload)
        return ParsedForm(fields=fields, files=files)

    if not body:
        return ParsedForm()
    raise ValueError("Content-Type form tidak didukung: {0}".format(content_type or "-"))


def _option_html(options: Sequence[str], selected_value: str) -> str:
    parts = []
    for option in options:
        selected = " selected" if option == selected_value else ""
        parts.append('<option value="{0}"{1}>{0}</option>'.format(option, selected))
    return "".join(parts)


def _textarea_block(label: str, value: str) -> str:
    return """
    <div class="result-block">
      <label>{label}</label>
      <textarea readonly>{value}</textarea>
    </div>
    """.format(label=escape(label), value=escape(value))


def _build_text_result_html(result: Optional[Dict[str, str]]) -> str:
    if not result:
        return ""
    status_class = "status-ok" if result["status"] == "ok" else "status-error"
    body = ['<section class="result-card {0}">'.format(status_class)]
    body.append("<h3>{0}</h3>".format(escape(result["title"])))
    body.append("<p>{0}</p>".format(escape(result["message"])))
    if result["status"] == "ok" and result["kind"] == "encrypt":
        body.append(
            """
            <div class="metadata-grid">
              <div><span>Mode</span><strong>{mode}</strong></div>
              <div><span>IV/Nonce</span><strong>{iv_hex}</strong></div>
              <div><span>Input</span><strong>{input_size} byte</strong></div>
              <div><span>Output</span><strong>{output_size} byte</strong></div>
            </div>
            """.format(
                mode=escape(result["payload"]["mode"]),
                iv_hex=escape(result["payload"]["iv_hex"]),
                input_size=result["payload"]["input_size"],
                output_size=result["payload"]["output_size"],
            )
        )
        body.append(_textarea_block("Ciphertext Hex", result["payload"]["ciphertext_hex"]))
        body.append(_textarea_block("Ciphertext Base64", result["payload"]["ciphertext_base64"]))
        body.append(_textarea_block("Payload Siap Tempel", result["payload"]["payload"]))
    elif result["status"] == "ok":
        body.append(
            """
            <div class="metadata-grid">
              <div><span>Mode</span><strong>{mode}</strong></div>
              <div><span>IV/Nonce</span><strong>{iv_hex}</strong></div>
              <div><span>Input</span><strong>{input_size} byte</strong></div>
              <div><span>Output</span><strong>{output_size} byte</strong></div>
            </div>
            """.format(
                mode=escape(result["payload"]["mode"]),
                iv_hex=escape(result["payload"]["iv_hex"]),
                input_size=result["payload"]["input_size"],
                output_size=result["payload"]["output_size"],
            )
        )
        body.append(_textarea_block("Plaintext", result["payload"]["plaintext"]))
    body.append("</section>")
    return "".join(body)


def _build_file_result_html(result: Optional[Dict[str, str]]) -> str:
    if not result:
        return ""
    status_class = "status-ok" if result["status"] == "ok" else "status-error"
    body = ['<section class="result-card {0}">'.format(status_class)]
    body.append("<h3>{0}</h3>".format(escape(result["title"])))
    body.append("<p>{0}</p>".format(escape(result["message"])))
    if result["status"] == "ok":
        payload = result["payload"]
        body.append(
            """
            <div class="metadata-grid">
              <div><span>Mode</span><strong>{mode}</strong></div>
              <div><span>IV/Nonce</span><strong>{iv_hex}</strong></div>
              <div><span>Input</span><strong>{input_size}</strong></div>
              <div><span>Output</span><strong>{output_size}</strong></div>
            </div>
            """.format(
                mode=escape(payload["mode"]),
                iv_hex=escape(payload["iv_hex"]),
                input_size=escape(payload["input_size_readable"]),
                output_size=escape(payload["output_size_readable"]),
            )
        )
        body.append(
            '<p><a class="download-link" href="/download/{0}">Unduh hasil: {1}</a></p>'.format(
                quote(payload["output_name"]),
                escape(payload["output_name"]),
            )
        )
        body.append(_textarea_block("Preview", payload["preview"]))
    body.append("</section>")
    return "".join(body)


def render_page(
    text_result: Optional[Dict[str, str]] = None,
    file_result: Optional[Dict[str, str]] = None,
    text_defaults: Optional[Dict[str, str]] = None,
    file_defaults: Optional[Dict[str, str]] = None,
) -> str:
    """Bangun halaman HTML utama."""
    text_defaults = text_defaults or {}
    file_defaults = file_defaults or {}
    text_action = text_defaults.get("action", "encrypt")
    file_action = file_defaults.get("action", "encrypt")
    text_html = _build_text_result_html(text_result)
    file_html = _build_file_result_html(file_result)
    return """<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Sistem Encrypt Decrypt</title>
  <link rel="stylesheet" href="/static/style.css">
</head>
<body>
  <main class="page-shell">
    <section class="panel-grid">
      <section class="panel">
        <div class="panel-header">
          <p class="section-tag">Operasi Teks</p>
          <h2>Encrypt / Decrypt Teks</h2>
        </div>
        <form action="/text" method="post" class="app-form">
          <div class="field-row">
            <div class="field">
              <label for="text-action">Aksi</label>
              <select id="text-action" name="action" onchange="syncTextForm()">
                <option value="encrypt"{text_encrypt_selected}>Encrypt</option>
                <option value="decrypt"{text_decrypt_selected}>Decrypt</option>
              </select>
            </div>
            <div class="field">
              <label for="text-mode">Mode Operasi</label>
              <select id="text-mode" name="mode">
                {mode_options}
              </select>
            </div>
          </div>

          <div class="field-row">
            <div class="field">
              <label for="text-key">Key</label>
              <input id="text-key" name="key" type="text" value="{text_key}" placeholder="Masukkan key user">
            </div>
            <div class="field">
              <label for="text-iv">IV / Nonce (hex 32 karakter)</label>
              <input id="text-iv" name="iv_hex" type="text" value="{text_iv}" placeholder="Kosongkan untuk auto-generate saat encrypt">
            </div>
          </div>

          <div class="field" id="text-input-format-row">
            <label for="text-input-format">Format Input Saat Decrypt</label>
            <select id="text-input-format" name="input_format">
              <option value="payload"{payload_selected}>Payload</option>
              <option value="hex"{hex_selected}>Hex</option>
              <option value="base64"{base64_selected}>Base64</option>
            </select>
          </div>

          <div class="field">
            <label for="text-value" id="text-value-label">Teks Masukan</label>
            <textarea id="text-value" name="text_value" placeholder="Masukkan plaintext atau ciphertext sesuai aksi">{text_value}</textarea>
          </div>

          <button type="submit" class="primary-button">Proses Teks</button>
          <p class="helper-text">
            Jika decrypt memakai format payload, mode dan IV/nonce akan dibaca otomatis dari payload.
          </p>
        </form>
        {text_html}
      </section>

      <section class="panel">
        <div class="panel-header">
          <p class="section-tag">Operasi File</p>
          <h2>Encrypt / Decrypt File</h2>
        </div>
        <form action="/file" method="post" enctype="multipart/form-data" class="app-form">
          <div class="field-row">
            <div class="field">
              <label for="file-action">Aksi</label>
              <select id="file-action" name="action">
                <option value="encrypt"{file_encrypt_selected}>Encrypt</option>
                <option value="decrypt"{file_decrypt_selected}>Decrypt</option>
              </select>
            </div>
            <div class="field">
              <label for="file-mode">Mode Saat Encrypt</label>
              <select id="file-mode" name="mode">
                {file_mode_options}
              </select>
            </div>
          </div>

          <div class="field-row">
            <div class="field">
              <label for="file-key">Key</label>
              <input id="file-key" name="key" type="text" value="{file_key}" placeholder="Masukkan key user">
            </div>
            <div class="field">
              <label for="file-iv">IV / Nonce (hex 32 karakter)</label>
              <input id="file-iv" name="iv_hex" type="text" value="{file_iv}" placeholder="Kosongkan untuk auto-generate saat encrypt">
            </div>
          </div>

          <div class="field">
            <label for="file-upload">File</label>
            <input id="file-upload" name="upload_file" type="file">
          </div>

          <button type="submit" class="primary-button">Proses File</button>
          <p class="helper-text">
            Saat decrypt file, aplikasi membaca mode, IV/nonce, checksum, dan nama file asli dari paket file terenkripsi.
          </p>
        </form>
        {file_html}
      </section>
    </section>
  </main>

  <script>
    function syncTextForm() {{
      const action = document.getElementById('text-action').value;
      const label = document.getElementById('text-value-label');
      const formatRow = document.getElementById('text-input-format-row');
      if (action === 'encrypt') {{
        label.textContent = 'Teks Masukan';
        formatRow.style.display = 'none';
      }} else {{
        label.textContent = 'Ciphertext / Payload';
        formatRow.style.display = 'block';
      }}
    }}
    window.addEventListener('DOMContentLoaded', syncTextForm);
  </script>
</body>
</html>
""".format(
        text_encrypt_selected=" selected" if text_action == "encrypt" else "",
        text_decrypt_selected=" selected" if text_action == "decrypt" else "",
        file_encrypt_selected=" selected" if file_action == "encrypt" else "",
        file_decrypt_selected=" selected" if file_action == "decrypt" else "",
        mode_options=_option_html(("ECB", "CBC", "CTR"), text_defaults.get("mode", "CBC")),
        file_mode_options=_option_html(("ECB", "CBC", "CTR"), file_defaults.get("mode", "CBC")),
        text_key=escape(text_defaults.get("key", "")),
        text_iv=escape(text_defaults.get("iv_hex", "")),
        text_value=escape(text_defaults.get("text_value", "")),
        file_key=escape(file_defaults.get("key", "")),
        file_iv=escape(file_defaults.get("iv_hex", "")),
        payload_selected=" selected" if text_defaults.get("input_format", "payload") == "payload" else "",
        hex_selected=" selected" if text_defaults.get("input_format", "payload") == "hex" else "",
        base64_selected=" selected" if text_defaults.get("input_format", "payload") == "base64" else "",
        text_html=text_html,
        file_html=file_html,
    )


class CryptoWebHandler(BaseHTTPRequestHandler):
    """Request handler untuk halaman utama, proses teks, proses file, dan download."""

    def do_GET(self) -> None:  # noqa: N802 - mengikuti interface BaseHTTPRequestHandler
        if self.path == "/" or self.path == "":
            self._send_html(render_page())
            return
        if self.path == "/static/style.css":
            self._send_file(STATIC_DIR / "style.css", "text/css; charset=utf-8")
            return
        if self.path.startswith("/download/"):
            filename = Path(unquote(self.path[len("/download/") :])).name
            if not filename:
                self.send_error(404, "File hasil tidak ditemukan.")
                return
            self._send_download(DEFAULT_OUTPUT_DIR / filename)
            return
        self.send_error(404, "Halaman tidak ditemukan.")

    def do_POST(self) -> None:  # noqa: N802 - mengikuti interface BaseHTTPRequestHandler
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_error(400, "Content-Length tidak valid.")
            return
        body = self.rfile.read(content_length)
        try:
            form = parse_http_form(self.headers.get("Content-Type", ""), body)
        except ValueError as exc:
            self.send_error(400, str(exc))
            return
        if self.path == "/text":
            self._handle_text_form(form)
            return
        if self.path == "/file":
            self._handle_file_form(form)
            return
        self.send_error(404, "Endpoint tidak ditemukan.")

    def log_message(self, format_string: str, *args: object) -> None:
        """Kurangi noise log agar demo lebih bersih."""
        return

    def _send_html(self, html_content: str) -> None:
        payload = html_content.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _send_file(self, file_path: Path, content_type: str) -> None:
        if not file_path.is_file():
            self.send_error(404, "File statis tidak ditemukan.")
            return
        payload = file_path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _send_download(self, file_path: Path) -> None:
        if not file_path.is_file():
            self.send_error(404, "File hasil tidak ditemukan.")
            return
        mime_type, _ = mimetypes.guess_type(str(file_path))
        payload = file_path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", mime_type or "application/octet-stream")
        self.send_header("Content-Disposition", 'attachment; filename="{0}"'.format(file_path.name))
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _handle_text_form(self, form: ParsedForm) -> None:
        defaults = {
            "action": form.getfirst("action", "encrypt"),
            "mode": form.getfirst("mode", "CBC"),
            "key": form.getfirst("key", ""),
            "iv_hex": form.getfirst("iv_hex", ""),
            "text_value": form.getfirst("text_value", ""),
            "input_format": form.getfirst("input_format", "payload"),
        }
        try:
            if defaults["action"] == "encrypt":
                payload = encrypt_text(
                    defaults["text_value"],
                    defaults["key"],
                    defaults["mode"],
                    defaults["iv_hex"],
                )
                result = {
                    "status": "ok",
                    "kind": "encrypt",
                    "title": "Enkripsi teks berhasil",
                    "message": "Ciphertext tersedia dalam format hex, base64, dan payload siap tempel.",
                    "payload": payload,
                }
            else:
                payload = decrypt_text(
                    defaults["text_value"],
                    defaults["key"],
                    input_format=defaults["input_format"],
                    mode=defaults["mode"],
                    iv_hex=defaults["iv_hex"],
                )
                result = {
                    "status": "ok",
                    "kind": "decrypt",
                    "title": "Dekripsi teks berhasil",
                    "message": "Plaintext berhasil dipulihkan dan diverifikasi bila input berupa payload.",
                    "payload": payload,
                }
        except Exception as exc:  # noqa: BLE001 - error ditampilkan ringkas untuk user
            result = {
                "status": "error",
                "kind": defaults["action"],
                "title": "Operasi teks gagal",
                "message": str(exc),
            }
        self._send_html(render_page(text_result=result, text_defaults=defaults))

    def _handle_file_form(self, form: ParsedForm) -> None:
        defaults = {
            "action": form.getfirst("action", "encrypt"),
            "mode": form.getfirst("mode", "CBC"),
            "key": form.getfirst("key", ""),
            "iv_hex": form.getfirst("iv_hex", ""),
        }
        try:
            upload_field = form.getfile("upload_file")
            if upload_field is None or not upload_field.filename:
                raise ValueError("Silakan pilih file yang ingin diproses.")
            file_bytes = upload_field.content
            filename = Path(upload_field.filename).name or "uploaded.bin"
            if defaults["action"] == "encrypt":
                payload = encrypt_file_bytes(
                    file_bytes,
                    filename,
                    defaults["key"],
                    defaults["mode"],
                    defaults["iv_hex"],
                )
                result = {
                    "status": "ok",
                    "title": "Enkripsi file berhasil",
                    "message": "Paket file terenkripsi berhasil dibuat dan siap diunduh.",
                    "payload": payload,
                }
            else:
                payload = decrypt_file_bytes(file_bytes, defaults["key"])
                result = {
                    "status": "ok",
                    "title": "Dekripsi file berhasil",
                    "message": "File asli berhasil dipulihkan dan disimpan ke folder outputs.",
                    "payload": payload,
                }
        except Exception as exc:  # noqa: BLE001
            result = {
                "status": "error",
                "title": "Operasi file gagal",
                "message": str(exc),
            }
        self._send_html(render_page(file_result=result, file_defaults=defaults))


def run_server(host: str = "127.0.0.1", port: int = 8000) -> None:
    """Jalankan Web UI sampai dihentikan user."""
    server = ThreadingHTTPServer((host, port), CryptoWebHandler)
    print("Web UI aktif di http://{0}:{1}".format(host, port))
    print("Tekan Ctrl+C untuk menghentikan server.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        print("\nServer dihentikan.")


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Entry point untuk root main.py atau python -m app.webapp."""
    parser = argparse.ArgumentParser(description="Jalankan Web UI Edu Cipher Lab.")
    parser.add_argument("--host", default="127.0.0.1", help="Host Web UI.")
    parser.add_argument("--port", type=int, default=8000, help="Port Web UI.")
    args = parser.parse_args(argv)
    run_server(args.host, args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
