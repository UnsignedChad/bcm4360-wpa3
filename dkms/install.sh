#!/bin/bash
# Install the patched wl driver via DKMS so it auto-rebuilds on kernel updates,
# and load it at boot before NetworkManager. Run from the repo root: dkms/install.sh
set -e
REPO="$(cd "$(dirname "$0")/.." && pwd)"
# name/version come from dkms.conf so there is a single source of truth
NAME=$(sed -n 's/^PACKAGE_NAME="\(.*\)"/\1/p' "$REPO/dkms/dkms.conf")
VER=$(sed -n 's/^PACKAGE_VERSION="\(.*\)"/\1/p' "$REPO/dkms/dkms.conf")
SRC=/usr/src/$NAME-$VER
ORIG="$REPO/wl-src/lib/wlc_hybrid.o_amd64.orig"

[ -f "$ORIG" ] || { echo "Put the pristine blob at wl-src/lib/wlc_hybrid.o_amd64.orig first (see README)"; exit 1; }
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }

echo "== assemble self-contained DKMS source at $SRC =="
rm -rf "$SRC"; mkdir -p "$SRC/lib" "$SRC/patches"
cp -a "$REPO/wl-src/Makefile" "$REPO/wl-src/src" "$SRC/"
# never ship stale objects from a previous ./build.sh into the DKMS tree (other kernel/flags)
find "$SRC" \( -name '*.o' -o -name '.*.cmd' -o -name '*.ko' -o -name '*.mod' -o -name '*.mod.c' \
     -o -name Module.symvers -o -name modules.order \) -delete
cp "$ORIG" "$SRC/lib/wlc_hybrid.o_amd64.orig"
cp "$REPO/patches/wl_patch.py" "$REPO/patches/wl_reloc.py" "$SRC/patches/"
cp "$REPO/dkms/dkms.conf" "$REPO/dkms/dkms-prebuild.sh" "$SRC/"
chmod +x "$SRC/dkms-prebuild.sh"

echo "== keep conflicting drivers off the card =="
cat > /etc/modprobe.d/wl-wpa3.conf <<'BL'
blacklist b43
blacklist b43legacy
blacklist bcma
blacklist brcm80211
blacklist brcmsmac
blacklist ssb
# stop udev from auto-binding wl; the boot service below loads it explicitly
blacklist wl
BL
if dkms status 2>/dev/null | grep -q '^broadcom-sta'; then
  echo "   NOTE: stock broadcom-sta-dkms is installed and also builds a 'wl' module."
  echo "   Remove it to avoid the conflict:  sudo apt-get purge broadcom-sta-dkms"
fi

echo "== dkms add + build + install =="
dkms remove -m $NAME -v $VER --all 2>/dev/null || true
dkms add -m $NAME -v $VER
dkms install -m $NAME -v $VER --force
dkms status -m $NAME

echo "== load at boot, before NetworkManager =="
cat > /etc/systemd/system/wl-wpa3.service <<'UNIT'
[Unit]
Description=BCM4360 WPA3 driver (DKMS)
Before=NetworkManager.service
After=systemd-modules-load.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/sbin/modprobe wl
ExecStartPost=/bin/sh -c 'for i in $(seq 1 25); do ls /sys/class/net/*/phy80211 >/dev/null 2>&1 && exit 0; sleep 0.2; done'
ExecStop=/sbin/rmmod wl

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now wl-wpa3.service

echo "== done -- wl loaded: $(lsmod | grep -c '^wl ') =="
echo "Now connect to your network from the NetworkManager wifi menu (WPA3-SAE)."
