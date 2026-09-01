#!/usr/bin/env bash
# Draws the sized icons the pages actually serve, from web/glarion-mark.png.
#
#   bash scripts/icons.sh
#
# Regenerate and commit the results; nothing builds these at deploy time, for
# the same reason og-image.sh does not: they change about once a year, and a
# deploy host needing an image toolchain would be a larger thing to maintain
# than four committed files.
#
# Why they exist at all: glarion-mark.png is 1254x1254 and 458 KB. It was
# serving as the favicon, the apple-touch icon, the PWA icon and the 26px
# wordmark next to the product name — which is on every page, three times on
# the landing. Every visitor was downloading 458 KB to draw a 26-pixel logo,
# before anything else on the page could finish. The 64px form is 4.5 KB.
#
# The source stays committed because this script and og-image.sh both read it.
# No page references it directly.
#
#   64   favicon, and the inline wordmark at 26 CSS px (2x and then some)
#   180  apple-touch-icon, the size iOS asks for
#   192  PWA manifest, the smallest Chrome will install from
#   512  PWA manifest, splash and install prompt
#
# Purpose is "any", not "any maskable": the mark fills its own frame, so a
# maskable circle would crop the outer ring off. Claiming a purpose the
# artwork cannot serve is worse than not claiming it.
set -euo pipefail

cd "$(dirname "$0")/.."

MARK="web/glarion-mark.png"
[ -f "$MARK" ] || { echo "missing $MARK" >&2; exit 1; }

command -v magick >/dev/null 2>&1 || {
  echo "ImageMagick (magick) is not on PATH" >&2
  exit 1
}

for size in 64 180 192 512; do
  out="web/glarion-mark-${size}.png"
  magick "$MARK" -resize "${size}x${size}" -strip \
    -define png:compression-level=9 "$out"
  wc -c <"$out" | awk -v f="$out" '{ printf "%-30s %6.1f KB", f, $1 / 1024; print "" }'
done
