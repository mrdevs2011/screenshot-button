# Screenshot Button

Bitta float tugma: bossangiz kompyuter ekrani skrinshoti brauzerga keladi.

## Ishlash

- Kompyuterda Flask (waitress) — port 8765
- Skrinshot: grim (Wayland) JPEG, RAM buffer (diskka saqlanmaydi)
- Auth: master token, 5 daqiqa faolsizlik sessiyasi
- Vercel: proksi (REMOTE_URL = ngrok .../shot)

## O'rnatish

./install.sh

systemctl --user status screenshot-button

Token: cat ~/.config/screenshot-button/token

## Ochish

- https://<ngrok>/shot
- https://screenshot-button.vercel.app

## UI

- Login: parol + Enter
- Bitta float ● (sudrab joylash)
- Bosish = shot; uzoq bosish / Esc = chiqish
- Zoom: pinch / scroll; double-click = download
