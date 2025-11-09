# yhds-vps-v4
# YHDS VPS v4

🌟 **YHDS VPS Menu v4** 🌟  
Menu VPS interaktif dengan tampilan neon/ASCII, mendukung pembuatan akun SSH, UDP-Custom, WS, Trojan, V2Ray, serta payload generator + pengiriman otomatis ke Telegram.

---

## Fitur

- Create SSH Account
- Create UDP-Custom Account
- Create WS Account
- Create Trojan Account
- Create V2Ray Account (VMESS / VLESS)
- List Users
- Remove User
- Restart UDP-Custom Service
- Check UDP-Custom Status
- Check Logs
- Auto Update Script
- Install / Restart Telegram Bot
- Tampilan ASCII neon keren + info VPS (hostname, OS, IP, RAM, Disk, dll.)
- Kirim payload ke Telegram (opsional, jika bot dikonfigurasi)

---

## Requirements

- Root akses
- VPS Debian / Ubuntu
- Dependensi:
  - `bash`
  - `curl`
  - `jq`
  - `figlet` (opsional untuk banner)
  - `lolcat` (opsional untuk warna neon)
  - `uuidgen` / `python3` (untuk VMESS/VLESS UUID)

---

## Instalasi & Jalankan

Jalankan 1 baris ini di VPS Anda:

```bash
wget -O /usr/local/bin/menu https://raw.githubusercontent.com/Yahdiad1/yhds-vps-v4/main/menu && chmod +x /usr/local/bin/menu && /usr/local/bin/menu


cat > /etc/yhds/README.md <<'EOF'
# YHDS VPS Full Menu v4

**Versi:** 4.0  
**Dibuat oleh:** YHDS Team  

Menu VPS premium all-in-one untuk **SSH, UDP Custom, WebSocket, Trojan, V2Ray placeholder**, termasuk:

- Mode **Wildcard** (IP-only atau domain) untuk WS/Trojan
- Auto-generate self-signed TLS certificate (IP ± domain)
- Auto-expire akun (mendukung menit/hari)
- Payload builder (VMESS / VLESS / TROJAN) + QR
- Telegram bot integrasi (opsional)
- UDP-Custom 1–65535, auto-start service
- Dashboard info server (CPU, RAM, Disk, IP, ISP, Uptime, Load, Wildcard)

---

## Persyaratan

- OS: Debian / Ubuntu (64-bit)
- Root akses
- Akses internet
- Port TCP 443 & 8443 terbuka
- Optional: `figlet`, `lolcat` untuk tampilan menu neon

---

## Instalasi

1. **Download script menu full:**

```bash
wget -O /usr/local/bin/menu_full_yhds_v4.sh https://raw.githubusercontent.com/Yahdiad1/yhds-vps-v4/main/menu_full_yhds_v4.sh
chmod +x /usr/local/bin/menu_full_yhds_v4.sh
