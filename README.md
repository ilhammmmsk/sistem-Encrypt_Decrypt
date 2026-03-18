# Edu Cipher Lab

Edu Cipher Lab adalah proyek aplikasi penyandian data digital berbasis Python murni untuk kebutuhan tugas kuliah/akademik. Aplikasi ini menyediakan enkripsi dan dekripsi teks maupun file menggunakan block cipher kustom buatan sendiri, lengkap dengan mode operasi `ECB`, `CBC`, dan `CTR`, Web UI sederhana, CLI fallback, dokumentasi teknis, sample file, serta pengujian dasar.

## Latar Belakang

Dalam mata kuliah keamanan sistem atau kriptografi, mahasiswa sering diminta memahami cara kerja block cipher dan mode operasinya secara konseptual, bukan sekadar memanggil library siap pakai. Proyek ini dibuat untuk menjawab kebutuhan tersebut:

- tidak memakai library kriptografi eksternal;
- merancang cipher blok edukatif dari nol;
- mengimplementasikan mode operasi secara manual;
- mendukung teks dan file biner;
- menampilkan hasil dalam bentuk yang mudah didemokan.

## Catatan Akademik Penting

- Cipher pada proyek ini **khusus untuk pembelajaran**.
- Implementasi ini **bukan standar industri** dan **tidak ditujukan untuk keamanan produksi**.
- Mode `ECB` tetap disediakan karena sering diminta dalam tugas, tetapi secara akademik merupakan pilihan dengan nilai paling rendah dan kurang direkomendasikan karena pola blok plaintext dapat tetap terlihat pada ciphertext.

## Fitur Utama

- Enkripsi teks langsung dari input pengguna.
- Dekripsi teks dari `payload`, `hex`, atau `base64`.
- Enkripsi file teks maupun file biner.
- Dekripsi file paket terenkripsi (`.edc`) ke file aslinya.
- Pilihan mode operasi `ECB`, `CBC`, dan `CTR`.
- Input key dari pengguna.
- IV/nonce dapat diisi manual atau digenerate otomatis saat enkripsi.
- Output teks dalam format `hex`, `base64`, dan `payload` siap tempel.
- Preview hasil untuk file teks.
- Penanganan bytes mentah untuk file biner agar data tetap utuh.
- Web UI berbasis Python standard library.
- CLI fallback untuk demo terminal atau pengujian cepat.

## Teknologi yang Digunakan

- Python 3.9+
- `http.server`
- `cgi`
- `argparse`
- `base64`
- `json`
- `pathlib`
- `unittest`

Tidak ada dependensi eksternal. File [requirements.txt](requirements.txt) hanya bersifat informatif.

## Struktur Folder

```text
sistem-Encrypt_Decrypt/
├── app/
│   ├── __init__.py
│   ├── cipher.py
│   ├── modes.py
│   ├── payload.py
│   ├── service.py
│   ├── cli.py
│   ├── webapp.py
│   └── static/
│       └── style.css
├── docs/
│   ├── ARCHITECTURE.md
│   ├── DEVELOPMENT_JOURNEY.md
│   └── USER_GUIDE.md
├── outputs/
├── samples/
│   ├── sample.txt
│   └── sample.bin
├── tests/
│   └── test_system.py
├── .gitignore
├── main.py
├── README.md
└── requirements.txt
```

## Cara Instalasi

1. Clone repository.
2. Masuk ke folder proyek.
3. Buat virtual environment bila diinginkan.
4. Jalankan aplikasi.

Contoh:

```bash
git clone <URL-REPOSITORY>
cd sistem-Encrypt_Decrypt
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Karena proyek ini memakai standard library, perintah `pip install -r requirements.txt` tidak akan menarik paket tambahan.

## Menjalankan Web UI

Cara paling sederhana:

```bash
python3 main.py --host 127.0.0.1 --port 8000
```

Lalu buka browser ke:

```text
http://127.0.0.1:8000
```

Alternatif:

```bash
python3 -m app.webapp --host 127.0.0.1 --port 8000
python3 -m app.cli web --host 127.0.0.1 --port 8000
```

## Menjalankan CLI

### Enkripsi teks

```bash
python3 -m app.cli text-encrypt \
  --mode CBC \
  --key "KunciKuliah123" \
  --text "Halo dunia akademik"
```

### Dekripsi teks dari payload

```bash
python3 -m app.cli text-decrypt \
  --key "KunciKuliah123" \
  --input "<payload_dari_hasil_enkripsi>" \
  --input-format payload
```

### Enkripsi file

```bash
python3 -m app.cli file-encrypt \
  --mode CTR \
  --key "KunciKuliah123" \
  --input samples/sample.txt
```

### Dekripsi file

```bash
python3 -m app.cli file-decrypt \
  --key "KunciKuliah123" \
  --input outputs/sample.txt.edc
```

## Cara Penggunaan untuk End User

### Teks

1. Buka Web UI.
2. Masuk ke panel `Operasi Teks`.
3. Pilih `Encrypt` atau `Decrypt`.
4. Pilih mode `ECB`, `CBC`, atau `CTR`.
5. Masukkan key.
6. Jika memakai `CBC` atau `CTR`, isi IV/nonce manual bila ingin tetap; jika dikosongkan saat enkripsi, sistem akan meng-generate otomatis.
7. Masukkan plaintext atau ciphertext.
8. Tekan tombol `Proses Teks`.

### File

1. Buka panel `Operasi File`.
2. Pilih `Encrypt` atau `Decrypt`.
3. Upload file.
4. Untuk enkripsi, pilih mode operasi dan masukkan key.
5. Untuk dekripsi, cukup upload file `.edc` dan masukkan key yang benar.
6. Unduh hasil dari link yang muncul pada halaman.

## Penjelasan Singkat Mode Operasi

### ECB

- Setiap blok plaintext dienkripsi secara mandiri.
- Implementasinya paling sederhana.
- Tidak memakai IV.
- Kelemahannya: blok plaintext yang sama akan menghasilkan blok ciphertext yang sama.

### CBC

- Setiap blok plaintext di-XOR dengan blok ciphertext sebelumnya.
- Membutuhkan IV 16 byte.
- Lebih baik dari ECB untuk menyamarkan pola data.

### CTR

- Cipher blok dipakai untuk menghasilkan keystream dari nonce/counter.
- Membutuhkan nonce/counter awal 16 byte.
- Tidak memakai padding.
- Enkripsi dan dekripsi menggunakan proses yang sama.

## Kenapa ECB Kurang Aman

ECB dianggap kurang aman karena struktur datanya mudah memunculkan pola berulang. Jika dua blok plaintext identik, hasil ciphertext juga identik. Dalam konteks akademik, mode ini tetap penting dipelajari sebagai pembanding, tetapi untuk penilaian biasanya dianggap memiliki kualitas paling rendah dibanding `CBC` dan `CTR`.

## Desain Cipher Singkat

Cipher inti pada proyek ini memakai pendekatan:

- ukuran blok `128-bit`;
- struktur `Feistel`;
- `12 ronde`;
- key schedule buatan sendiri;
- round function yang menggabungkan:
  - XOR;
  - substitusi byte menggunakan S-Box kustom;
  - permutasi byte;
  - rotasi bit;
  - penambahan modulo `2^64`;
  - whitening key.

## Format Output

### Hasil enkripsi teks

- `hex`: representasi heksadesimal ciphertext.
- `base64`: representasi base64 ciphertext.
- `payload`: format praktis yang sudah memuat mode, IV/nonce, checksum, dan ciphertext. Ini format yang paling mudah dipakai kembali untuk dekripsi teks.

### Hasil enkripsi file

- File hasil disimpan sebagai paket `.edc`.
- Paket menyimpan metadata:
  - mode operasi;
  - IV/nonce;
  - nama file asli;
  - ukuran asli;
  - checksum sederhana untuk verifikasi.

## Pengujian

Pengujian otomatis tersedia pada folder [tests](tests). Jalankan:

```bash
python3 -m unittest discover -s tests -v
```

Skenario uji yang dicakup:

- enkripsi lalu dekripsi teks untuk `ECB`, `CBC`, dan `CTR`;
- enkripsi lalu dekripsi file `.txt`;
- enkripsi lalu dekripsi file biner;
- verifikasi round-trip mode operasi pada bytes mentah;
- uji kunci salah pada payload teks.

## Troubleshooting

### Port 8000 sudah dipakai

Jalankan dengan port lain:

```bash
python3 main.py --port 8080
```

### Dekripsi gagal pada mode CBC atau CTR

Periksa:

- key yang dipakai harus sama;
- IV/nonce manual harus sama dengan saat enkripsi jika tidak memakai payload;
- input hex harus 32 karakter untuk IV/nonce 16 byte.

### File hasil tidak bisa dipulihkan

Kemungkinan penyebab:

- key salah;
- file `.edc` rusak atau terpotong;
- file yang didekripsi bukan paket hasil aplikasi ini.

### Browser tidak bisa mengunduh hasil

Pastikan proses server masih berjalan dan file hasil berada di folder `outputs/`.

## Batasan Sistem

- Cipher ini bersifat edukatif, bukan standar kriptografi modern.
- Tidak ada autentikasi kriptografis tingkat produksi.
- Integritas file/payload diperiksa dengan checksum sederhana, bukan MAC standar industri.
- UI dibuat sederhana agar mudah dipahami dan mudah didemokan di kelas.

## Dokumentasi Tambahan

- [Arsitektur](docs/ARCHITECTURE.md)
- [Perjalanan Pengembangan](docs/DEVELOPMENT_JOURNEY.md)
- [Panduan Pengguna](docs/USER_GUIDE.md)

## Ringkasan

Repo ini sudah berisi source code aplikasi, Web UI, CLI, sample file, test, dan dokumentasi lengkap dalam bahasa Indonesia sehingga siap dipakai untuk tugas kuliah, demo presentasi, maupun diunggah ke GitHub.
