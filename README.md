# Screenshot Button

Bitta tugma: bossangiz kompyuter ekrani skrinshot qilinib, brauzeringizga (telefon yoki boshqa qurilma) keladi.

## Qanday ishlaydi

- `app.py` kompyuterda kichik Flask server ishga tushiradi.
- Sahifadagi **Skrinshot qilish** tugmasi `POST /api/screenshot` ni chaqiradi.
- Server `grim` (Wayland), `scrot` yoki `import` (X11) orqali ekranni oladi va PNG qaytaradi.
- Skrinshot serverda saqlanmaydi: vaqtinchalik fayl o'qilgach darhol o'chiriladi.

## Ishga tushirish

```bash
pip install -r requirements.txt
./run.sh
```

Server `http://127.0.0.1:8765` da ochiladi. Birinchi ishga tushishda token yaratiladi va `.token` fayliga yoziladi:

```bash
cat .token
```

Brauzerda sahifani oching, tokenni bir marta kiriting va tugmani bosing.

## Boshqa qurilmadan ochish (telefon)

Server faqat o'z kompyuteringizda (`127.0.0.1`) tinglaydi. Tashqaridan ochish uchun tunnel ishlating:

```bash
cloudflared tunnel --url http://127.0.0.1:8765
```

yoki `ngrok http 8765`, yoki Tailscale. Chiqqan HTTPS manzilni telefonda oching.

## Xavfsizlik

Bu dastur ekraningizni ko'rsatadi, shuning uchun:

- Token'ni hech kimga bermang va GitHub'ga yuklamang (`.token` `.gitignore` da).
- Token'ni almashtirish uchun `.token` ni o'chirib, serverni qayta ishga tushiring.
- Tunnelni faqat kerak bo'lganda yoqing.

## Sozlamalar (muhit o'zgaruvchilari)

| O'zgaruvchi | Standart | Izoh |
|---|---|---|
| `PORT` | `8765` | Server porti |
| `HOST` | `127.0.0.1` | Tinglash manzili |
| `SCREENSHOT_TOKEN` | avtomatik | O'z tokeningizni berish |
