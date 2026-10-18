#!/bin/bash
# Build the WPA3/PMF-bridged wl.ko from the PRISTINE Broadcom blob (reproducible):
#   byte-patch (P1) -> globalize bridge symbols -> repoint auth relocs to our hooks -> relink.
set -e
ROOT="$(cd "$(dirname "$0")" && pwd)"
DEV="$ROOT/wl-src"
KVER="${KVER:-$(uname -r)}"
ORIG="$DEV/lib/wlc_hybrid.o_amd64.orig"   # YOU provide this (see README)
BLOB="$DEV/lib/wlc_hybrid.o_amd64"
export BLOB

if [ ! -f "$ORIG" ]; then
  echo "ERROR: missing $ORIG"
  echo "Get it from broadcom-sta 6.30.223.271:"
  echo "  the file is hybrid-v35_64-nodebug-pcoem-6_30_223_271.tar.gz -> lib/wlc_hybrid.o_amd64"
  echo "  copy it to wl-src/lib/wlc_hybrid.o_amd64.orig"
  exit 1
fi

echo "== start from pristine blob =="
cp "$ORIG" "$BLOB"
echo "== P1 byte patch (auth-clamp passthrough -> allow SAE alg=3) =="
python3 "$ROOT/patches/wl_patch.py" "$BLOB" --apply | sed 's/^/   /'
echo "== globalize blob-internal bridge symbols + mint re_auth_advance =="
GLOBS="wlc_sendauth wlc_sendmgmt wlc_queue_80211_frag wlc_frame_get_mgmt wlc_frame_get_mgmt_ex \
       wlc_sup_set_pmk wlc_authresp_client wlc_recv wlc_scbfind wlc_bsscfg_find_by_bssid"
objcopy $(printf -- '--globalize-symbol=%s ' $GLOBS) \
        --add-symbol re_auth_advance=.text:0x5b79d,global,function \
        "$BLOB" "$BLOB.g" && mv "$BLOB.g" "$BLOB"
echo "== repoint auth call relocs (wlc_recv/sendauth/authresp) -> __wrap_* hooks =="
python3 "$ROOT/patches/wl_reloc.py" "$BLOB" | sed 's/^/   /'
echo "== build (KVER=$KVER) =="
cd "$DEV"
make clean >/dev/null 2>&1 || true
if make KVER="$KVER" > "$ROOT/build.log" 2>&1; then
  grep -iE 'error|warning: objtool' "$ROOT/build.log" | head || true
  ls -la --time-style=+%H:%M:%S "$DEV/wl.ko"
  echo "BUILD OK -> $DEV/wl.ko"
else
  echo "BUILD FAILED:"; grep -iE 'error:' "$ROOT/build.log" | head -20; exit 1
fi
