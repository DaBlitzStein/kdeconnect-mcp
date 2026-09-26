#!/usr/bin/env bash
# Renderiza un diagrama mermaid con Firefox headless (sin Chrome).
# Uso: tools/render-mermaid.sh entrada.mmd salida.svg|png
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IN="${1:?uso: render-mermaid.sh entrada.mmd salida.svg|png}"
OUT="${2:?uso: render-mermaid.sh entrada.mmd salida.svg|png}"
PUPPETEER_SKIP_DOWNLOAD=1 npx -y @mermaid-js/mermaid-cli \
  -p "$DIR/puppeteer.firefox.json" -i "$IN" -o "$OUT"
