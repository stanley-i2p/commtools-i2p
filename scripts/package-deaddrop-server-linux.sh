#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 VERSION" >&2
    exit 2
fi

version="$1"

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_dir="$(cd -- "$script_dir/.." && pwd)"
dist_dir="${DIST_DIR:-$project_dir/dist}"
stage_dir="${DEADDROP_SERVER_PACKAGE_STAGE_DIR:-$project_dir/.deaddrop-server-linux-package}"
binary="$project_dir/deaddrop-server/target/release/deaddrop-server"
readme="$project_dir/deaddrop-server/README.md"
license="$project_dir/LICENSE"
notice="$project_dir/NOTICE"
commercial_licensing="$project_dir/COMMERCIAL-LICENSING.md"
archive_name="deaddrop-server-v${version}-linux-x86_64-gnu"
portable_dir="$stage_dir/$archive_name"

for required in "$binary" "$readme" "$license" "$notice" "$commercial_licensing"; do
    if [[ ! -f "$required" ]]; then
        echo "Required server packaging input is missing: $required" >&2
        exit 1
    fi
done

if [[ ! -x "$binary" ]]; then
    echo "Server release binary is not executable: $binary" >&2
    exit 1
fi

rm -rf -- "$stage_dir"
mkdir -p -- "$dist_dir" "$portable_dir"

install -m 755 -- "$binary" "$portable_dir/deaddrop-server"
install -m 644 -- "$readme" "$portable_dir/README.md"
install -m 644 -- "$license" "$portable_dir/LICENSE"
install -m 644 -- "$notice" "$portable_dir/NOTICE"
install -m 644 -- "$commercial_licensing" "$portable_dir/COMMERCIAL-LICENSING.md"

tar \
    --sort=name \
    --owner=0 \
    --group=0 \
    --numeric-owner \
    --mtime="@${SOURCE_DATE_EPOCH:-0}" \
    -C "$stage_dir" \
    -cf - \
    "$archive_name" \
    | gzip -n -9 > "$dist_dir/$archive_name.tar.gz"
