#!/bin/sh
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$SCRIPT_DIR/.."

if command -v magick >/dev/null 2>&1; then
  IM_CMD="magick"
elif command -v convert >/dev/null 2>&1; then
  IM_CMD="convert"
else
  echo "ERROR: Neither magick (IM7) nor convert (IM6) found" >&2
  exit 1
fi

SIZES="40 96 160 300"
STATES="NORM NONNORM CRIT META"
BACKGROUNDS="transparent dark white"

DIRS="go-server/static/exports/owl-semaphore static/exports/owl-semaphore"

generated=0

for dir in $DIRS; do
  SRC_DIR="$ROOT/$dir"
  OUT_DIR="$SRC_DIR/derived"

  if [ ! -d "$SRC_DIR" ]; then
    continue
  fi

  mkdir -p "$OUT_DIR"

  for state in $STATES; do
    for bg in $BACKGROUNDS; do
      src="$SRC_DIR/${state}-composite-${bg}-540.png"
      if [ ! -f "$src" ]; then
        continue
      fi
      for size in $SIZES; do
        base="${state}-composite-${bg}-w${size}"
        png_out="$OUT_DIR/${base}.png"
        webp_out="$OUT_DIR/${base}.webp"

        if [ ! -f "$png_out" ]; then
          $IM_CMD "$src" -resize "${size}x${size}" -strip "$png_out"
          generated=$((generated + 1))
        fi

        if [ ! -f "$webp_out" ]; then
          cwebp -q 90 -m 6 -resize "$size" "$size" "$png_out" -o "$webp_out" 2>/dev/null
          generated=$((generated + 1))
        fi
      done
    done
  done
done

if [ "$generated" -gt 0 ]; then
  echo "Generated $generated new owl derived assets"
else
  echo "Owl derived assets up to date"
fi
