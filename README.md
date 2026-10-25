# Screenshot Button

Bitta float tugma: bossangiz kompyuter ekrani skrinshoti brauzerga keladi.
Uzoq bossangiz **video rejimi** yoqiladi: ekran 5 soniyalik bo'laklarda yozilib, to'xtamasdan (loop) brauzerga uzatiladi.

## Ishlash

- Kompyuterda Flask (waitress) — port 8765
- Skrinshot: grim (Wayland) JPEG, RAM buffer (diskka saqlanmaydi)
- Video: wf-recorder + ffmpeg (H.264) -> 5 soniyalik MP4 segmentlar, faqat RAM (`/dev/shm`), oxirgi 24 tasi (~2 daqiqa) saqlanadi
- Auth: master token, 5 daqiqa faolsizlik sessiyasi (video rejimida 30 daqiqa)
- Vercel: proksi (REMOTE_URL = ngrok .../shot)

## O'rnatish

./install.sh

Video rejimi uchun `wf-recorder` va `ffmpeg` o'rnatilgan bo'lishi kerak.

systemctl --user status screenshot-button

Token: cat ~/.config/screenshot-button/token

## Ochish

- https://<ngrok>/shot
- https://screenshot-button.vercel.app

## UI

- Login: parol + Enter
- Bitta float ● (sudrab joylash)
- **Skrinshot rejimi:** bosish = shot; uzoq bosish (~0.7s) = video rejimiga o'tish
- **Video rejimi (▶):** ekran yozilib, ~5-10 soniya ortda uzluksiz ijro etiladi; chapda `-10s` kabi kechikish ko'rsatiladi
  - bosish = jonli chetga sakrash; chapga/o'ngga surish (yoki ←/→) = oldingi/keyingi 5 soniyalik bo'lak
  - uzoq bosish = yana skrinshot rejimiga qaytish (yozuv to'xtaydi va RAM'dagi fayllar o'chadi)
- Klaviatura: Space/Enter/S = bosish, V = rejim almashtirish, Esc = chiqish (logout)
- Zoom (skrinshot): pinch / scroll; double-click = download

## Sozlamalar (`~/.config/screenshot-button/config.env`, ixtiyoriy)

| O'zgaruvchi | Standart | Izoh |
|---|---|---|
| VIDEO_SEG | 5 | segment uzunligi (soniya) |
| VIDEO_FPS | 15 | kadr/soniya |
| VIDEO_WIDTH | 1280 | maksimal eni (px) |
| VIDEO_CRF | 30 | sifat (kichikroq = yaxshiroq) |
| VIDEO_MAXRATE | 3000k | bitreyt chegarasi (segment ~2 MB dan oshmaydi) |
| VIDEO_KEEP | 24 | nechta oxirgi segment saqlansin |
| VIDEO_OUTPUT | — | bir nechta monitor bo'lsa, monitor nomi (wf-recorder -o) |

## Maxfiylik

Yozuv faqat video rejimi yoqilgan va brauzer segment so'rab turgan paytda ishlaydi (30 soniya so'rov kelmasa to'xtaydi). Videolar diskka yozilmaydi.

## Yozib olish (bosib turib)

- Tugmani uzoq bosish (~0.7s) = yozuv boshlanadi: faqat qizil tugma va `● REC 0:07` sekund hisoblagichi ko'rinadi.
- Yana uzoq bosish = yozuv to'xtaydi, video bo'laklab (1 MB) yuklab olinadi va o'ynaydi; yuqori o'ngdagi ⬇ bilan saqlanadi.
- Tez bosish: video ochiq bo'lsa yopadi, bo'lmasa skrinshot oladi.
- Sozlamalar: `CLIP_WIDTH` (1280), `CLIP_FPS` (12), `CLIP_CRF` (30), `CLIP_MAXRATE` (800k), `CLIP_MAX_SECONDS` (600).
- Yozuv RAM'da (`/dev/shm`), yuklab olingach o'chiriladi. Eski jonli segment rejimi kodda qolgan, lekin tugmaga ulanmagan.
