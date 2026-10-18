# DKMS install (auto-rebuild on kernel updates)

The module is built per-kernel, so a kernel upgrade needs a rebuild. DKMS automates that.

```sh
# 1. drop the pristine Broadcom blob in place (see the main README):
cp /path/to/wlc_hybrid.o_amd64 wl-src/lib/wlc_hybrid.o_amd64.orig
# 2. install:
sudo dkms/install.sh
```

This registers `wl-wpa3/<version>` (from `dkms.conf`), builds the **patched** module, blacklists the in-tree drivers and
the stock `wl`, and loads ours at boot before NetworkManager. Connect from the wifi GUI.

## The one thing that bites you

`dkms.conf` **must** run `PRE_BUILD="dkms-prebuild.sh"`. That script applies the byte-patch +
symbol-globalize + reloc-redirect to the blob *in the DKMS build directory* before `make`.
The stock `broadcom-sta` `dkms.conf` has no such step — if you reuse it, DKMS compiles the
**unpatched** blob and you get a driver that associates and scans forever but never completes
WPA3-SAE (0 `__wrap_*` hooks, 0 P1 bytes in the `.ko`). Always pass the blob path to the patch
scripts (`wl_patch.py "$BLOB"`, `wl_reloc.py "$BLOB"`) so they patch the build's blob, not a
stale checkout.

## Files

- `dkms.conf` — package definition with the all-important `PRE_BUILD`.
- `dkms-prebuild.sh` — turns the pristine blob into the hooked one (mirrors `../build.sh`).
- `install.sh` — assembles a self-contained `/usr/src/wl-wpa3-<version>`, runs DKMS, sets up boot load.
