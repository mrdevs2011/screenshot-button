#!/usr/bin/env bash
# Shu kompyuterga o'rnatadi: venv + config papka + systemd user servis.
# Kod shu papkada lokal turadi (GitHub'ga bog'liq emas). Sozlamalar ~/.config/screenshot-button/ da.
set -euo pipefail
APP_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG_DIR="${SCREENSHOT_CONFIG_DIR:-$HOME/.config/screenshot-button}"
UNIT_DIR="$HOME/.config/systemd/user"

python3 -m venv "$APP_DIR/.venv"
"$APP_DIR/.venv/bin/pip" install -q -r "$APP_DIR/requirements.txt"

mkdir -p "$CONFIG_DIR" "$UNIT_DIR"
chmod 700 "$CONFIG_DIR"
if [ ! -f "$CONFIG_DIR/config.env" ]; then
  cat > "$CONFIG_DIR/config.env" <<CFG
# Shu kompyuterga xos sozlamalar (GitHub'ga yuklanmaydi)
HOST=127.0.0.1
PORT=8765
CFG
fi

if command -v fish >/dev/null 2>&1; then
  mkdir -p "$HOME/.config/fish/functions"
  cp "$APP_DIR/deploy/scrsettok.fish" "$HOME/.config/fish/functions/scrsettok.fish"
fi

sed -e "s#@APP_DIR@#$APP_DIR#g" -e "s#@CONFIG_DIR@#$CONFIG_DIR#g" \
  "$APP_DIR/deploy/screenshot-button.service.template" > "$UNIT_DIR/screenshot-button.service"

systemctl --user daemon-reload
systemctl --user enable --now screenshot-button.service
loginctl show-user "$(id -un)" -p Linger | grep -q "Linger=yes" \
  || echo "ESLATMA: login qilmasdan ham ishlashi uchun: sudo loginctl enable-linger $(id -un)"
sleep 1
systemctl --user --no-pager status screenshot-button.service | head -8
