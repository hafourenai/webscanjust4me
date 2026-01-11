# 🍯 HONEY Vulnerability Scanner



## 📁 Struktur Project

```
├── honey_scanner/     # Paket modul utama
│   ├── core/          # Engine (Scanner, Config, WAF Bypass)
│   ├── detection/     # Verifikasi (SQLi, XSS, LFI, CSRF)
│   ├── antiban/       # Anti-blocking (Proxy, Tor, Limiter)
│   └── reporting/     # Multi-format reporter
├── Payloads/          # Database payload lokal (Dapat diedit)
├── config.yaml        # Konfigurasi aplikasi
├── main.py            # Entry point
└── pyproject.toml     # Packaging standar Python
```

## Instalasi & Penggunaan

### 1. Setup Environment
```bash
# Clone & Masuk direktori
git clone https://github.com/hafourenai/webscanjust4me
cd webscanjust4me

<<<<<<< HEAD
# Install dependencies
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
=======
# Install dependencies (Rekomendasi)
pip install -e .
>>>>>>> 4462ddb (Last Commit)
```

### 2. Cara Menjalankan Scanner
Anda dapat menjalankan scanner dengan dua cara:

#### **Metode A: Terinstal (Rekomendasi)**
Jalankan langsung dari terminal setelah melakukan `pip install -e .` di atas:
```bash
honey-scanner <target_url> [options]
```

#### **Metode B: Tanpa Instalasi**
Jalankan langsung melalui file `main.py`:
```bash
python main.py <target_url> [options]
```

## Konfigurasi
Anda dapat menyesuaikan perilaku scanner di `config.yaml`, seperti:
- Jumlah thread default.
- Batas kedalaman crawler.
- Lokasi file payload.
- Pengaturan retry dan anti-block.

## Contoh Command
```bash
# Scan dengan mode stealth & rate limit rendah
honey-scanner https://target.com --stealth --rate 0.5

# Scan agresif dengan banyak thread
honey-scanner https://target.com --aggressive --threads 20
```

<<<<<<< HEAD
#### **2. Stealth Scan (Production Sites)**
```bash
python main.py http://target.com --stealth --depth 7 --threads 10 --rate 0.5
```

#### **3. Scan with Proxy Protection**
```bash
python main.py http://target.com --proxy-file proxies.txt --stealth --rate 0.5
```
#### **4. Maximum Anonymity (TOR + Proxies)**
```bash
# Start TOR
sudo service tor start

python main.py http://target.com --proxy-file proxies.txt --use-tor --stealth --rate 0.2 -d 5

# Stop TOR
sudo service tor stop
```

#### **5. Aggressive Bug Bounty Scan**
```bash
python main.py http://target.com --aggressive --threads 20 --depth 10 --rate 2.0
```

#### **6. High-Value Target (Cloudflare/WAF)**
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
=======
>>>>>>> 4462ddb (Last Commit)

---

> [!IMPORTANT]
> **Legal Disclaimer:** Gunakan tools ini hanya untuk tujuan edukasi dan pengujian keamanan yang sah secara hukum. Penyalahgunaan terhadap target tanpa izin tertulis adalah sepenuhnya tanggung jawab pengguna.
