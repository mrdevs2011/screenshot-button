function scrsettok --description "Skrinshot tokenini ko'rsatadi va xohlasangiz yangilaydi"
    set -l cfg $HOME/.config/screenshot-button
    if set -q SCREENSHOT_CONFIG_DIR
        set cfg $SCREENSHOT_CONFIG_DIR
    end
    set -l file $cfg/token

    if test -s $file
        echo "Hozirgi token: "(cat $file | string trim)
    else
        echo "Hozirgi token: (yo'q)"
    end
    echo

    read -l -P "Yangi token qo'yamizmi? Davom etish: Enter, bekor qilish: Ctrl+C " _ok
    or begin
        echo
        echo "Bekor qilindi, token o'zgarmadi."
        return 1
    end

    read -l -P "Yangi token (bo'sh qoldirsangiz avtomatik yaratiladi): " new
    or begin
        echo
        echo "Bekor qilindi, token o'zgarmadi."
        return 1
    end
    set new (string trim -- $new)

    if test -z "$new"
        set new (python3 -c "import secrets; print(secrets.token_urlsafe(24))")
    else if string match -qr '\s' -- $new
        echo "Token ichida bo'sh joy bo'lmasligi kerak. Token o'zgarmadi."
        return 1
    else if test (string length -- $new) -lt 16
        echo "Token juda qisqa (kamida 16 belgi kerak). Token o'zgarmadi."
        return 1
    end

    mkdir -p $cfg
    chmod 700 $cfg
    set -l tmp (mktemp $cfg/token.XXXXXX)
    echo $new > $tmp
    chmod 600 $tmp
    mv $tmp $file

    systemctl --user restart screenshot-button
    and echo "Servis qayta ishga tushdi."
    echo
    echo "Yangi token: $new"
    echo "Eslatma: boshqa qurilmalardagi sahifa yangi tokenni so'raydi."
end
