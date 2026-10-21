#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_dir"

if [ "$#" -eq 0 ]; then
    set -- 8.2.34 8.3.35 8.4.26 8.5.11
fi

for version do
    printf '%s\n' "=== PHP $version ==="
    ./run.sh "$version"
done

printf '%s\n' 'All requested Docker integration profiles passed.'
