#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
target_os="${GOOS:-$(go env GOOS)}"
target_arch="${GOARCH:-$(go env GOARCH)}"
output_dir="${1:-bin/naive/${target_os}-${target_arch}}"
mkdir -p "$output_dir"
tags="with_gvisor,with_naive"
binary="mihomo"

case "$target_os/$target_arch" in
  linux/amd64|linux/arm64|windows/amd64|windows/arm64)
    tags="$tags,with_purego"
    export CGO_ENABLED=0
    library_module="github.com/sagernet/cronet-go/lib/${target_os}_${target_arch}"
    # Use the native revision selected by cronet-go/all. Its generated package
    # commit can differ from the commit that contains the compiled libraries.
    version=$(go list -m -f '{{.Version}}' "$library_module")
    library_dir=$(go mod download -json "${library_module}@${version}" |
      python3 -c 'import json,sys; m=json.load(sys.stdin); print(m["Dir"])')
    library="libcronet.so"
    if [[ "$target_os" == windows ]]; then
      library="libcronet.dll"
      binary="mihomo.exe"
    fi
    # Go's module cache is read-only; create a writable artifact so subsequent
    # builds can replace it without a permissions error.
    install -m 0644 "$library_dir/$library" "$output_dir/$library"
    ;;
  darwin/amd64|darwin/arm64)
    # Apple builds link the prebuilt static library through CGO/Xcode.
    export CGO_ENABLED=1
    ;;
  *)
    echo "Unsupported automatic Naive build: $target_os/$target_arch. See docs/naive.md for native toolchain builds." >&2
    exit 1
    ;;
esac

version=$(git describe --tags --always --dirty)
GOOS="$target_os" GOARCH="$target_arch" go build -trimpath -tags "$tags" \
  -ldflags "-s -w -X github.com/metacubex/mihomo/constant.Version=$version" \
  -o "$output_dir/$binary" .
echo "Built $output_dir/$binary (tags: $tags)"
