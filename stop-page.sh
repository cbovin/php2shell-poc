#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$repo_dir"

docker compose \
    --project-name php-rce-page \
    --file compose.yaml \
    --file compose.page.yaml \
    down --volumes --remove-orphans
