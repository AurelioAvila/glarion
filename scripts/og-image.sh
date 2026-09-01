#!/usr/bin/env bash
# Draws web/og.png, the picture a link to Glarion shows when it is shared.
#
#   bash scripts/og-image.sh
#
# Regenerate and commit the result; nothing builds this at deploy time. It is
# one file that changes about once a year, and a build step needing an image
# toolchain on the deploy host would be a larger thing to maintain than the
# file itself.
#
# Why a landscape card and not the square mark on its own: the mark alone,
# under twitter:card=summary, renders as a thumbnail beside the title. The
# 1200x630 form under summary_large_image renders as a full-width card, which
# is roughly twice the footprint in the places these links actually get
# shared — a Slack channel or a DM far more often than a public timeline.
# The tags are read by Slack, Discord and iMessage too, so this matters
# whether or not the product has an account anywhere.
#
# Light, not dark like the landing page, because glarion-mark.png is drawn for
# a light ground: its outer ring is near-black and would disappear on the
# product's own background. Compositing the real asset rather than redrawing
# an approximation of it is worth more than matching the site's palette here.
#
# The card still follows the landing page's rule: colour means security state
# and nothing else. The only colour is the mark's own accent dot and the row
# of real states, which is the vocabulary the reports speak.

set -euo pipefail

cd "$(dirname "$0")/.."

INK="#0b0b0c"
INK_2="#5c6470"
INK_3="#8b9199"
RULE="#e2e5ea"
CLEAR="#3fb984"
CAUTION="#d99320"
ALARM="#e0503a"

OUT="web/og.png"
MARK="web/glarion-mark.png"

[ -f "$MARK" ] || { echo "missing $MARK" >&2; exit 1; }

# The mark, scaled once into a temporary so the composite below is a plain
# overlay rather than a resize inside a longer command.
TMP="$(mktemp -t glarion-mark-XXXXXX).png"
trap 'rm -f "$TMP"' EXIT
magick "$MARK" -resize 168x168 "$TMP"

magick -size 1200x630 xc:white \
    "$TMP" -geometry +84+92 -composite \
    -font Segoe-UI-Bold -pointsize 60 -fill "${INK}" \
    -annotate +284+168 "Glarion" \
    -font Segoe-UI -pointsize 27 -fill "${INK_2}" \
    -annotate +286+214 "Security monitoring for the sites you look after." \
    -font Segoe-UI -pointsize 26 -fill "${INK_2}" \
    -annotate +84+300 "One account covers every client site. Ownership is proven before anything" \
    -annotate +84+338 "is scanned, and the report is one you can hand the client." \
    -fill "${RULE}" -draw "rectangle 84,470 1116,470" \
    -fill "${CLEAR}" -draw "circle 92,518 92,524" \
    -fill "${CAUTION}" -draw "circle 250,518 250,524" \
    -fill "${ALARM}" -draw "circle 470,518 470,524" \
    -font Consolas -pointsize 22 -fill "${INK_3}" \
    -annotate +112+525 "clear" \
    -annotate +270+525 "worth fixing" \
    -annotate +490+525 "act now" \
    -annotate +968+525 "glarion.app" \
    -depth 8 -strip "${OUT}"

magick identify "${OUT}"
