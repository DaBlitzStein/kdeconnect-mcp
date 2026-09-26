#!/usr/bin/env bash
# Renderiza un .mmd a PNG (Firefox headless) y lo muestra en la terminal con chafa.
# Uso: tools/show-mermaid.sh archivo.mmd [WxH]
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IN="${1:?uso: show-mermaid.sh archivo.mmd [WxH]}"
SIZE="${2:-110x55}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
"$DIR/render-mermaid.sh" "$IN" "$TMP/out.png" >/dev/null
chafa --size "$SIZE" "$TMP/out.png"
