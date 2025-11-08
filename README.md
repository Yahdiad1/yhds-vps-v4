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
