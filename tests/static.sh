#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_dir"

export PYTHONDONTWRITEBYTECODE=1

python3 -m unittest discover --start-directory tests --pattern 'test_*.py'
python3 -m py_compile poc.py tests/test_poc.py
sh -n run.sh start-page.sh stop-page.sh versions.sh \
    k8s/deploy-and-test.sh tests/static.sh tests/integration.sh

if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    docker compose --project-name php-rce-static --file compose.yaml config --quiet
else
    printf '%s\n' 'SKIP: Docker Compose is unavailable; Compose render not checked.'
fi

if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    git diff --check
fi

printf '%s\n' 'Static and unit checks passed.'
