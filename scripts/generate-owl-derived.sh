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

if ! command -v cwebp >/dev/null 2>&1; then
  echo "ERROR: cwebp not found" >&2
  exit 1
fi

SIZES="40 96 160 300"
STATES="NORM NONNORM CRIT META"
BACKGROUNDS="transparent dark white"

DIRS="go-server/static/exports/owl-semaphore static/exports/owl-semaphore"

generated=0
regenerated=0

needs_build() {
  [ ! -s "$1" ]
}

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
      if [ ! -s "$src" ]; then
        echo "ERROR: source asset is zero bytes: $src" >&2
        exit 1
      fi
      for size in $SIZES; do
        base="${state}-composite-${bg}-w${size}"
        png_out="$OUT_DIR/${base}.png"
        webp_out="$OUT_DIR/${base}.webp"

        if needs_build "$png_out"; then
          [ -f "$png_out" ] && { rm -f "$png_out"; regenerated=$((regenerated + 1)); }
          if ! $IM_CMD "$src" -resize "${size}x${size}" -strip "$png_out"; then
            echo "ERROR: $IM_CMD failed for $png_out" >&2
            rm -f "$png_out"
            exit 1
          fi
          if [ ! -s "$png_out" ]; then
            echo "ERROR: $IM_CMD produced zero-byte output: $png_out" >&2
            rm -f "$png_out"
            exit 1
          fi
          generated=$((generated + 1))
        fi

        if needs_build "$webp_out"; then
          [ -f "$webp_out" ] && { rm -f "$webp_out"; regenerated=$((regenerated + 1)); }
          if ! cwebp -q 90 -m 6 -resize "$size" "$size" "$png_out" -o "$webp_out"; then
            echo "ERROR: cwebp failed for $webp_out" >&2
            rm -f "$webp_out"
            exit 1
          fi
          if [ ! -s "$webp_out" ]; then
            echo "ERROR: cwebp produced zero-byte output: $webp_out" >&2
            rm -f "$webp_out"
            exit 1
          fi
          generated=$((generated + 1))
        fi
      done
    done
  done

  zero_byte=$(find "$OUT_DIR" -type f -size 0 2>/dev/null || true)
  if [ -n "$zero_byte" ]; then
    echo "ERROR: zero-byte derived assets detected in $OUT_DIR:" >&2
    echo "$zero_byte" >&2
    exit 1
  fi
done

if [ "$regenerated" -gt 0 ]; then
  echo "Regenerated $regenerated stale (zero-byte) derived assets"
fi

if [ "$generated" -gt 0 ]; then
  echo "Generated $generated owl derived assets"
else
  echo "Owl derived assets up to date"
fi
