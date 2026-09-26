#!/usr/bin/env bash
# Muestra un diagrama mermaid en ASCII (flowchart y sequence).
# Uso: tools/mmd.sh archivo.mmd [--ascii]
set -euo pipefail
IN="${1:?uso: mmd.sh archivo.mmd [--ascii]}"
shift || true
exec mermaid-ascii -f "$IN" "$@"
