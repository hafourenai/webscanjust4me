# 🍯 HONEY Vulnerability Scanner

## 📁 Struktur Project
```
├── honey_scanner/     # Paket modul utama
│   ├── core/          # Engine (Scanner, Config, WAF Bypass)
│   ├── detection/     # Verifikasi (SQLi, XSS, LFI, CSRF)
│   ├── antiban/       # Anti-blocking (Proxy, Tor, Limiter)
│   ├── reporting/     # Multi-format reporter
│   └── resources/     # Internal resources (Payloads, etc.)
├── reports/           # Direktori output laporan (Otomatis)
├── logs/              # Direktori log aplikasi (Otomatis)
├── config.yaml        # Konfigurasi aplikasi
├── pyproject.toml     # Packaging standar Python
└── Dockerfile         # Kontainerisasi siap produksi
```

## Instalasi & Penggunaan


### Setup Environment
=======
### 1. Lokal (Python)
```bash
# Install sebagai package lokal
pip install .

# Jalankan scanner
honey-scanner <target_url> [options]
```

### 2. Docker (Kontainer)
```bash
# Build image
docker build -t honey-scanner .

# Jalankan scan (Laporan akan tersimpan di folder 'reports' lokal)
docker run --rm -v ${PWD}/reports:/app/reports honey-scanner <target_url>
```

## Konfigurasi
Anda dapat menyesuaikan perilaku scanner di `config.yaml` atau menggunakan **Environment Variables** (Sangat direkomendasikan untuk Docker/CI-CD):

| Variabel Lingkungan | Contoh Nilai | Deskripsi |
|--------------------|--------------|-----------|
| `HONEY_SCANNING_THREADS` | `20` | Jumlah thread paralel |
| `HONEY_SCANNING_TIMEOUT` | `15` | Timeout request dalam detik |
| `HONEY_SCANNING_DEFAULT_RATE_LIMIT` | `2.0` | Request per detik |

## Contoh Command

# Scan agresif dengan banyak thread
honey-scanner https://target.com --aggressive --threads 20
```
#### **Standard Scan**
```bash
honey-scanner http://target.com
```

#### **Stealth Scan (Produksi)**
```bash
honey-scanner http://target.com --stealth --rate 0.5
```

#### **Anonymous Scan (TOR + Proxy)**
```bash
honey-scanner http://target.com --use-tor --proxy-file proxies.txt
```


#### **High-Value Target (Cloudflare/WAF)**
```bash
python main.py http://target.com --proxy-file proxies.txt --use-tor --stealth --rate 0.1 --threads 3 -d 3
```
#### **Clean**
```bash
python clean.py
```
### Opsi Command Line
- `-t, --threads`: Jumlah thread (default: 15).
- `-d, --depth`: Kedalaman crawling (default: 5).
- `--stealth`: Mode senyap (delay antar request lebih lama).
- `--aggressive`: Mode agresif (delay minimal).
- `--proxy-file`: Path ke file list proxy.
- `--use-tor`: Gunakan jaringan TOR.
- `--rate`: Batasi request per detik (e.g., `--rate 1.0`).
---

> [!IMPORTANT]
> **Legal Disclaimer:** Gunakan tools ini hanya untuk tujuan edukasi dan pengujian keamanan yang sah secara hukum. Penyalahgunaan terhadap target tanpa izin tertulis adalah sepenuhnya tanggung jawab pengguna.
