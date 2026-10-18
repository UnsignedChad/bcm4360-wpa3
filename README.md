# WPA3-SAE + 802.11w on the Broadcom BCM4360 (closed `wl` blob)

Apple/Broadcom never gave the **BCM4360** (`14e4:43a0`) WPA3. Its only Linux driver is the
closed `broadcom-sta` (`wl`) blob; `brcmfmac` can't drive it. This adds **WPA3-SAE + full
802.11w PMF** to that closed blob — entirely from host software, **no firmware source**.

Proven on-air vs a WPA3-only, MFP-required AP: SAE auth → assoc → 4-way → CCMP data, stable,
and resistant to **deauth-flood** *and* **SA-Query teardown** attacks.

## How it works

The blob is a **non-stripped, relocatable ELF `.o`** (not a final firmware image) — that is the
whole reason this works. We don't rewrite it; we **link new C against it** and **redirect a few
call sites**:

- `wpa_supplicant` runs SAE + the 4-way (the blob's crypto is SHA-1-only; SAE needs SHA-256).
- A small cfg80211 glue (`wl_cfg80211_hybrid.c`, `wl_linux.c`) bridges auth/assoc/keys.
- Three build steps make the blob hookable:
  1. **P1 byte-patch** — un-clamp the `auth` iovar so it accepts SAE (alg=3).
  2. **`objcopy --globalize-symbol`** — make ~10 blob-internal functions callable from our C.
  3. **`wl_reloc.py`** — rewrite `.rela.text` so the blob's calls to
     `wlc_recv`/`wlc_sendauth`/`wlc_authresp_client` land in our `__wrap_*` hooks.

That's enough to drive SAE frames over the air, inject `wpa_supplicant`'s RSN IE into the
assoc-req, install userspace-derived keys, and add software PMF (drop unprotected deauth;
SW-CCMP answer SA-Queries).

## Reverse engineering

Tools: Ghidra (headless), `nm`, `objdump`, `strings`, a monitor-mode sniffer (`iw` + `tcpdump`).

```sh
# 1. The blob ships inside broadcom-sta and is NOT stripped (~4091 syms) -> Ghidra recovers names.
GHIDRA=/opt/ghidra
$GHIDRA/support/analyzeHeadless ./proj wl -import wlc_hybrid.o_amd64 \
    -analysisTimeoutPerFile 3600          # auto-analyze, then decompile in the GUI

# 2. Triage what's present BEFORE picking a strategy (absent crypto must move host-side):
nm wlc_hybrid.o_amd64 | grep -iE 'sha256|sae|bip|igtk|mmie'          # -> empty here
nm wlc_hybrid.o_amd64 | grep -iE 'wpa|akm|sup|sendauth|key_insert'

# 3. Verify any offset before you patch it (.text vaddr V == file offset V+0x40 in this blob):
objdump -d --start-address=0x47d40 --stop-address=0x47d60 wlc_hybrid.o_amd64
```

Strategy: start at the cfg80211 entry points in the **open** glue (`wl_cfg80211_connect`,
`wl_set_auth_type`) and follow the iovars (`auth`, `wpa_auth`, `wsec`) into the blob. Decompile
what they reach: the AKM gate (`bcmwpa_akm2WPAauth`), the join/auth FSM (`wlc_join_BSS` + the
auth→assoc advancer at `0x5b79d`), the RX dispatch (`wlc_recv`), and the PMK/key path
(`wlc_sup_set_pmk`, `wlc_key_insert`). Cross-check every address with `objdump`.

## Porting to another chip

1. Confirm the blob is a **non-stripped relocatable `.o`** (`file`, `nm`). A stripped firmware
   image won't work this way.
2. In Ghidra find: the **auth-alg clamp**, the **join→auth→assoc FSM** + its "auth-succeeded"
   advancer, the **RX dispatch**, and `set_pmk`/key-insert.
3. Put their addresses in `build.sh` (`--add-symbol re_auth_advance=...`, the globalize list) and
   `patches/wl_reloc.py` (the `__wrap_*` targets).
4. Fix the struct offsets in `wl_linux.c` (`wlc+0x6a8` txq, `bsscfg+0x320` assoc, `scb+0x18` bss)
   — these are layout and **differ per blob version**.
5. Iterate on-air with a sniffer; firmware faults are kernel panics — capture `dmesg` over the
   network (see Struggles).

## Struggles → solutions

- **Kernel hard-locks during SAE, no backtrace.** A `--add-symbol` address was off by one hex
  digit (`0x15b79d` vs `0x5b79d`), landing mid-instruction → `call <garbage>` → NX fault.
  *Verify every synthetic symbol is a real function start (`objdump -d --start-address=...`).
  (Older kernels flagged this at build time with `objtool: ... can't find starting instruction`;
  since Linux 6.15 objtool cannot process the blob at all, so the Makefile skips it for the final
  `wl.o` link and that safety net is gone.)*
- **Can't capture the panic.** efi-pstore is broken on Apple EFI; netconsole can't TX over a
  USB-ethernet NIC. *Stream `dmesg --follow` over SSH to a second machine — it flushes the oops
  before the reboot.*
- **AP rejects assoc (status 31, MFP policy).** The blob builds its own PSK/no-MFP RSN IE.
  *Capture `wpa_supplicant`'s `sme->ie` in `.connect` and point the blob's assoc-req IE buffer
  (`*(bsscfg+0x320)+0x30`) at it — also satisfies the 4-way's RSN-IE check.*
- **Key install fails `-22`** — only the IGTK (BIP, idx 4); the HW key engine has no BIP slot.
  *Accept the IGTK in software; PTK/GTK install fine and data flows.*
- **Blob never decrypts management frames**, so 802.11w SA-Queries arrive as ciphertext.
  *Capture the PTK and do AES-CCM in software (kernel `ccm(aes)`) to read the query and emit an
  encrypted response.*

## Build

Needs kernel headers, `gcc`, `binutils`, `python3`. The blob is **not** in this repo (proprietary).
Builds against Linux 6.12 through 7.3 (see *Tested* below).

```sh
# 1. Get the pristine blob from broadcom-sta 6.30.223.271:
#    hybrid-v35_64-nodebug-pcoem-6_30_223_271.tar.gz  ->  lib/wlc_hybrid.o_amd64
cp /path/to/wlc_hybrid.o_amd64 wl-src/lib/wlc_hybrid.o_amd64.orig
#    Debian/Ubuntu: it is the same file the broadcom-sta-dkms package ships
#    (sha256 352a6e349f74c69b78e76f68c63752c99b8f6b22dc942af531b754211d7f4743):
#      sudo apt install broadcom-sta-dkms   # then, instead of the cp above:
#      cp /usr/src/broadcom-sta-6.30.223.271/lib/wlc_hybrid.o_amd64 wl-src/lib/wlc_hybrid.o_amd64.orig
#    (remove/blacklist that package's own `wl` afterwards, it conflicts with ours)
mkdir -p wl-src/lib

# 2. Build:
./build.sh                 # -> wl-src/wl.ko   (or download it from Releases)
```

## Install

### Quick test
```sh
sudo rmmod b43 brcmfmac bcma ssb wl 2>/dev/null   # free the card
sudo insmod wl-src/wl.ko                          # a wifi interface appears (wlan0, wlp3s0, ...)
```
**NetworkManager drives WPA3-SAE through this driver** — just use the wifi GUI: pick your network,
enter the password, done. NM saves it and auto-reconnects on every boot. CLI equivalent:
```sh
nmcli con add type wifi ifname YOUR_IFNAME con-name w ssid "YOUR_SSID"
nmcli con modify w wifi-sec.key-mgmt sae wifi-sec.psk "YOUR_PASS" 802-11-wireless-security.pmf 3
nmcli con up w        # NM does SAE + 4-way + DHCP
```
(Standalone alternative: `sudo ./examples/connect.sh [ifname] examples/wpa3-sae.conf.example`;
the interface name defaults to the first wireless interface.)

### Persistent (survives reboot + kernel updates)
```sh
sudo dkms/install.sh
```
Registers the driver with DKMS (auto-rebuilds on kernel upgrades), blacklists the conflicting
in-tree drivers + the stock `wl`, and loads ours at boot before NetworkManager. Then connect from
the wifi GUI. Details and the one DKMS gotcha: [`dkms/README.md`](dkms/README.md). For a one-off
manual rebuild instead, run `./build.sh` → `wl-src/wl.ko`.

### Debug logging
The driver is quiet by default. For a bug report, or to watch the WPA3/PMF state machine, enable
verbose logging (BSSIDs and the RSN IE are logged, so scrub them before posting):
```sh
echo 1 | sudo tee /sys/module/wl/parameters/re_verbose          # this boot: state machine, EAPOL, firmware events
echo 2 | sudo tee /sys/module/wl/parameters/re_verbose          # + the blob's TX/RX counters every 5 s
echo 'options wl re_verbose=1' | sudo tee /etc/modprobe.d/wl-debug.conf   # permanent
```

### Throughput with PMF (WPA3) and Block Ack
With 802.11w the AP protects its Block-Ack action frames (ADDBA/DELBA), which the blob cannot
decrypt, and drops the blob's own unprotected ones. Without a Block-Ack agreement there is no frame
aggregation and the AP keeps re-sending its ADDBA Request: SAE ran at about 14 Mbit/s with 17% TX
retries where WPA2-PSK reached about 190 Mbit/s. The driver now decrypts the AP's Block-Ack frames in
software and hands them to the blob, and CCMP-protects the blob's own, so the agreement is set up
normally (SAE 150-210 Mbit/s down, 0% retries on the same link). Module parameter `re_pmf_ba`:
`2` (default) = full, `1` = decline the AP's ADDBA (no aggregation), `0` = off.

### Stalled-link recovery (PMF / WPA3)
In soak tests under load a PMF link occasionally went bad without any deauth: after a scan the blob's rate
control ran away to its top rate and almost nothing we sent was ACKed any more (about one retry per frame),
while the stack kept showing "connected" until the connection was restarted by hand. The driver now watches
the retry counters in 12 s windows (windows containing a scan are ignored, scans always cost a burst of
retries). A window with retries >= 70% of the frames sent triggers an SA Query probe; no answer drops the
link, and if the AP answers but the link stays that bad for 3 windows (about 36 s) the link is dropped
anyway (opt-in, `re_pmf_stall=2`), so wpa_supplicant reconnects (a few seconds). Module parameter `re_pmf_stall`: `1` (default) =
probe only, `0` = off, `2` = probe and drop, `3` = test mode (every window counts as bad). The drop is not the default
because an idle 2.4 GHz link showed false alarms overnight (about one retry per frame, SA Query answered). The cause of the rate
runaway itself is not understood (it was seen 4 times in about 60 scans with the Block-Ack handling above, and
never in about 150 scans without it).

### Replacing Ubuntu/Debian's stock `wl` (broadcom-sta-dkms) permanently
Both packages provide a module named `wl`, so the stock one has to go. In the repo directory:
```sh
# 1. keep the pristine blob (the stock package's copy is the right one; same sha256 as above)
mkdir -p wl-src/lib
cp /usr/src/broadcom-sta-*/lib/wlc_hybrid.o_amd64 wl-src/lib/wlc_hybrid.o_amd64.orig
# 2. remove the stock driver (otherwise it is rebuilt for every new kernel and fights over the name `wl`)
sudo apt purge broadcom-sta-dkms        # (broadcom-sta-common is pulled out with it)
# 3. install ours via DKMS: rebuilt automatically for every new kernel, loaded at boot before NetworkManager
sudo dkms/install.sh
# 4. check
dkms status                             # wl-wpa3/<version>, installed
modinfo wl | grep -E "filename|description"    # .../updates/dkms/wl.ko*, "...WPA3-SAE and 802.11w (PMF) support"
systemctl status wl-wpa3.service
```
Then set your network profile to WPA3 (see below), reboot once and check `nmcli dev` shows the wifi
device. With Secure Boot enabled the module must be signed (DKMS signs it with your enrolled MOK on
Ubuntu); with it disabled nothing is needed.

To go back: `sudo dkms remove wl-wpa3/<version> --all`, `sudo systemctl disable --now wl-wpa3`,
remove `/etc/modprobe.d/wl-wpa3.conf` and `/etc/systemd/system/wl-wpa3.service`, and
`sudo apt install broadcom-sta-dkms`.

## WPA2/WPA3 transition-mode APs

Use a **WPA3 (SAE)** profile on the client; a `wpa-psk` profile connects with WPA2 by design:
```sh
nmcli con modify YOUR_CON wifi-sec.key-mgmt sae 802-11-wireless-security.pmf 3
```
On a FRITZ!Box 6690 in WPA2/WPA3 mixed mode this is stable: 45 min soaks with an AP group-key rekey every
10 min, 16 back-to-back disconnect/reconnect cycles, suspend/resume.

What had to be fixed to get there (details in the commit messages):
- **The association request was malformed.** SAE connects carry `wpa_versions = WPA3`, which the glue did not
  know, so the blob ran with WPA off and added a bogus legacy-WPA IE; we also pasted wpa_supplicant's whole IE
  buffer next to the blob's own, duplicating Extended Capabilities. The AP accepted such a station but then
  failed every group-key rekey, deauthenticated it, and the link sat "up" but dead. Now only the RSN/RSNX
  elements are injected and `wpa_auth` is right from the start.
- **The AP dropping us used to be invisible.** Its management frames are CCMP-protected (the blob can't
  decrypt them) and unprotected deauths are filtered. Now a protected deauth/disassoc is verified in software
  and honoured, an unprotected "class 2/3" deauth triggers a software SA Query (no answer -> reconnect), and
  the association is probed after resume.
- **Two races/bugs in the glue:** the host SAE exchange could start before the blob's own stub auth frame
  (which made the AP drop the join; it now follows the stub), and the cfg80211 BSS lookup used pre-4.1
  arguments so a connect could be silently discarded when the scan entry had expired.
- **Bounded reconnect time.** A failed join (the AP answers "try again later", or not at all, when the BSS
  we just left is re-joined) is retried silently up to 3 times; an association with no 4-way handshake is
  dropped after 3.5 s instead of 10 s; the protected deauth sent on disconnect is retransmitted if the
  firmware reports it un-ACKed; there are at least 2 s between a disconnect and the next join.

If the AP uses the same SSID on 2.4 and 5 GHz, wpa_supplicant picks the stronger BSS; pin one with
`802-11-wireless.band a|bg` or `802-11-wireless.bssid` if you want.

**Known issues**
- Re-joining the BSS you just left is the AP's weak spot (FRITZ!Box: "try again later" / no answer in
  30-40% of back-to-back reconnects). The driver absorbs it; the cost is an occasional ~5 s reconnect instead
  of ~1-2 s. WPA2-PSK median 1.7 s, max 5.4 s; SAE 0.3-1.1 s in 16-cycle stress tests.
- The blob knows nothing about 802.11w, so the driver handles the PMF parts of the Block-Ack setup in
  software (see below). If the module cannot get a synchronous `ccm(aes)` implementation, that is
  disabled and SAE/PMF sessions run without frame aggregation (slow). `re_pmf_ba=0` turns it off.
- PMF only works with WPA3-SAE here: the blob builds the RSN element of a WPA2-PSK join itself, without PMF.
  NetworkManager does not ask for PMF on WPA2-PSK profiles (its PMF setting is ignored there); a direct
  wpa_supplicant config with `ieee80211w=2` and WPA-PSK is refused instead of connecting without PMF.
- Not tested: a WPA3-only AP on this version, other APs than the FRITZ!Box 6690, 6.12-7.2 beyond building.

## Tested

| Kernel | How | Result |
|---|---|---|
| 7.3.0-9 (Ubuntu 26.10) | loaded and used, Intel MacBookPro11,1 (BCM4360), FRITZ!Box 6690 in WPA2/WPA3 mixed mode (2.4 + 5 GHz, same SSID) | 45 min SAE soak: 529 pings, 0 outages, 6 AP rekeys accepted; 16 + 16 back-to-back reconnects (SAE / WPA2) all connected, none over 5.4 s; WPA2-PSK and SAE profiles switch without reloading; clean `rmmod`/`insmod`; wrong password fails cleanly; suspend/resume reconnects by itself; no kernel warnings |
| 6.12, 6.14, 6.17, 7.0, 7.1, 7.2 | build only, against the mainline-PPA header packages | builds |
| 6.12 (Debian 13) | loaded and used, MacBookPro11,3, WPA3-only AP (previous release) | worked |

## Caveats

- The blob (`wlc_hybrid.o_amd64`) is **Broadcom proprietary** — get it from broadcom-sta yourself.
  The `wl.ko` in Releases embeds it (same situation as Debian's `broadcom-sta-dkms`).
- Offsets are specific to broadcom-sta **6.30.223.271 / BCM4360**.
- A prebuilt `wl.ko` is tied to the exact kernel it was built for (`vermagic`); build from source
  (or use DKMS) for any other kernel.
- Research code. License: GPL-2.0 (this wrapper) + Broadcom's license (the blob).
