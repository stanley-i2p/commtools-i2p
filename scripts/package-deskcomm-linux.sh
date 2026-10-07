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
desktop_file="$project_dir/packaging/linux/deskcomm-i2p.desktop"
icon="$project_dir/crates/deskcomm-i2p/assets/commtools-i2p.png"
documents=(
    "$project_dir/LICENSE"
    "$project_dir/NOTICE"
    "$project_dir/README.md"
    "$project_dir/COMMERCIAL-LICENSING.md"
)
package_name="deskcomm-i2p-v${version}-linux-x86_64-gnu"
package_dir="$stage_dir/$package_name"

for required in "$binary" "$desktop_file" "$icon" "${documents[@]}"; do
    if [[ ! -f "$required" ]]; then
        echo "Required DeskComm packaging input is missing: $required" >&2
        exit 1
    fi
done

if [[ ! -x "$binary" ]]; then
    echo "Release binary is not executable: $binary" >&2
    exit 1
fi

rm -rf -- "$stage_dir" "$dist_dir"
mkdir -p -- \
    "$package_dir/share/applications" \
    "$package_dir/share/icons/hicolor/128x128/apps" \
    "$dist_dir"
install -m 755 -- "$binary" "$package_dir/deskcomm-i2p"
install -m 644 -- "$desktop_file" "$package_dir/share/applications/deskcomm-i2p.desktop"
install -m 644 -- "$icon" "$package_dir/share/icons/hicolor/128x128/apps/deskcomm-i2p.png"
for document in "${documents[@]}"; do
    install -m 644 -- "$document" "$package_dir/$(basename -- "$document")"
done

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
