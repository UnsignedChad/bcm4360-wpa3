#!/bin/bash
# Connect the BCM4360 to a WPA3-SAE network (standalone wpa_supplicant, no NetworkManager).
# Usage: sudo ./connect.sh [ifname] [conf]
# ifname defaults to the first wireless interface once wl is loaded (e.g. wlan0 or wlp3s0).
set -e
CONF="${2:-$(dirname "$0")/wpa3-sae.conf.example}"
KO="$(dirname "$0")/../wl-src/wl.ko"

[ -n "$1" ] && pkill -9 -f "wpa_supplicant.*$1" 2>/dev/null || true
rmmod wl 2>/dev/null || true
insmod "$KO"
IF="$1"
for _ in $(seq 1 25); do   # wait for the wireless interface to appear
	[ -n "$IF" ] && [ -e "/sys/class/net/$IF" ] && break
	[ -z "$1" ] && IF="$(ls /sys/class/net/*/phy80211 2>/dev/null | head -n1 | cut -d/ -f5)"
	sleep 0.2
done
[ -n "$IF" ] && [ -e "/sys/class/net/$IF" ] || { echo "no wireless interface found"; exit 1; }

pkill -9 -f "wpa_supplicant.*$IF" 2>/dev/null || true
nmcli dev set "$IF" managed no 2>/dev/null || true   # keep NetworkManager off it
ip link set "$IF" up
wpa_supplicant -B -i "$IF" -D nl80211 -c "$CONF"
sleep 4
dhclient -1 "$IF" || udhcpc -i "$IF" -n -q || true
ip -4 addr show "$IF"
echo "connected on $IF"
