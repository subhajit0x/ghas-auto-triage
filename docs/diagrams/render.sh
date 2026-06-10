#!/usr/bin/env bash
# Render all .mmd files in this directory to PNG (and SVG).
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

CONFIG="$DIR/mermaid-config.json"
if [[ ! -f "$CONFIG" ]]; then
  cat >"$CONFIG" <<'EOF'
{
  "theme": "neutral",
  "themeVariables": {
    "fontFamily": "Helvetica, Arial, sans-serif",
    "fontSize": "14px"
  },
  "flowchart": {
    "htmlLabels": true,
    "curve": "basis"
  }
}
EOF
fi

echo "Rendering Mermaid diagrams in $DIR ..."
for mmd in *.mmd; do
  base="${mmd%.mmd}"
  echo "  $mmd -> ${base}.png"
  npx --yes @mermaid-js/mermaid-cli@11.4.0 \
    -i "$mmd" \
    -o "${base}.png" \
    -b white \
    -w 1920 \
    -H 1080 \
    -c "$CONFIG" \
    --scale 2
  npx --yes @mermaid-js/mermaid-cli@11.4.0 \
    -i "$mmd" \
    -o "${base}.svg" \
    -b white \
    -c "$CONFIG"
done
echo "Done."
