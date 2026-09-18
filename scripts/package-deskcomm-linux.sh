#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 VERSION" >&2
    exit 2
fi

version="$1"
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_dir="$(cd -- "$script_dir/.." && pwd)"
dist_dir="$project_dir/dist"
stage_dir="$project_dir/.deskcomm-linux-package"
binary="$project_dir/target/release/deskcomm-i2p"
package_name="deskcomm-i2p-v${version}-linux-x86_64-gnu"
package_dir="$stage_dir/$package_name"

if [[ ! -x "$binary" ]]; then
    echo "Release binary is missing or is not executable: $binary" >&2
    exit 1
fi

rm -rf -- "$stage_dir" "$dist_dir"
mkdir -p -- "$package_dir" "$dist_dir"
install -m 755 -- "$binary" "$package_dir/deskcomm-i2p"

tar \
    --sort=name \
    --owner=0 \
    --group=0 \
    --numeric-owner \
    --mtime="@${SOURCE_DATE_EPOCH:-0}" \
    -C "$stage_dir" \
    -cf - \
    "$package_name" \
    | gzip -n -9 > "$dist_dir/$package_name.tar.gz"

(
    cd "$dist_dir"
    sha256sum "$package_name.tar.gz" > SHA256SUMS
)
