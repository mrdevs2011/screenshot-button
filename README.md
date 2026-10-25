# Screenshot Button

Bitta tugma: bossangiz kompyuter ekrani skrinshot qilinib, brauzeringizga (telefon yoki boshqa qurilma) keladi.

## Qanday ishlaydi

- `app.py` kompyuterda kichik Flask server ishga tushiradi (`waitress` bilan).
- Sahifadagi **Skrinshot qilish** tugmasi `POST /api/screenshot` ni chaqiradi.
- Server `grim` (Wayland), `scrot` yoki `import` (X11) orqali ekranni oladi va PNG qaytaradi.
- Skrinshot serverda saqlanmaydi: vaqtinchalik fayl o'qilgach darhol o'chiriladi.
- Backend shu kompyuterning o'zida ishlaydi. GitHub'dan hech narsa tortilmaydi, repo o'chib ketsa ham servis ishlayveradi.

## O'rnatish (har bir kompyuterda bir marta)

```bash
./install.sh
```

Bu skript `.venv` yaratadi, `~/.config/screenshot-button/` papkasini tayyorlaydi va `systemd --user` servisini yoqadi. Servis kompyuter qayta ishga tushganda o'zi ko'tariladi, o'chib qolsa qayta yonadi.

Login qilmasdan ham ishlashi uchun bir marta: `sudo loginctl enable-linger $USER`.
Skrinshot olish uchun esa grafik sessiya (Wayland/X11) ochiq bo'lishi kerak.

## Sozlamalar: `~/.config/screenshot-button/`

Kod papkasidan tashqarida, har bir kompyuterda o'zining nusxasi bor va GitHub'ga yuklanmaydi.

| Fayl | Vazifasi |
|---|---|
| `config.env` | `HOST` (standart `127.0.0.1`), `PORT` (standart `8765`) |
| `token` | kirish tokeni (birinchi ishga tushishda avtomatik yaratiladi, ruxsat 600) |

Tokenni ko'rish: `cat ~/.config/screenshot-button/token`. Almashtirish uchun faylni o'chirib, servisni qayta ishga tushiring.
Boshqa papka ishlatish uchun: `SCREENSHOT_CONFIG_DIR=/yo/l`.

## Boshqarish

```bash
systemctl --user status screenshot-button
systemctl --user restart screenshot-button
journalctl --user -u screenshot-button -f
```

## Boshqa qurilmadan ochish

Server faqat `127.0.0.1` da tinglaydi. Tashqaridan ochish uchun tunnel kerak (Tailscale, ngrok yoki cloudflared).

## Xavfsizlik

Bu dastur ekraningizni ko'rsatadi: tokenni hech kimga bermang, tunnelni faqat kerakli qurilmalarga oching.

## Vercel (proksi rejimi)

Vercel'da `grim` ham, ekran ham yo'q, shuning uchun u yerda kod avtomatik proksi rejimiga o'tadi (`VERCEL` o'zgaruvchisi bo'yicha): faqat sahifani ko'rsatadi va `/api/screenshot` so'rovini kompyuterdagi serverga uzatadi. Token Vercel'da saqlanmaydi, u brauzerdan to'g'ridan-to'g'ri o'tadi.

Vercel'da bitta o'zgaruvchi kerak: `REMOTE_URL` = kompyuterning ommaviy tunnel manzili (masalan `https://xxxx.ngrok-free.app`). Usiz tugma "manzil sozlanmagan" xabarini beradi.
