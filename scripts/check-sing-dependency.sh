#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
modules=$(go list -m -f '{{.Path}}' all)
printf '%s\n' "$modules" | awk '
  $0 == "github.com/sagernet/sing" { print "unexpected SagerNet/sing module" > "/dev/stderr"; failed = 1 }
  END { exit failed }
'

for tags in "" "${1:-}"; do
  packages=$(go list -deps -tags "$tags" .)
  printf '%s\n' "$packages" | awk '
    /^github.com\/sagernet\/sing(\/|$)/ { print "unexpected package: " $0 > "/dev/stderr"; failed = 1 }
    END { exit failed }
  '
done
