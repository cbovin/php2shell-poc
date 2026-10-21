#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$repo_dir"

. "$repo_dir/versions.sh"
select_php_version "${1:-8.4.26}"

compose() {
    docker compose \
        --project-name php-rce-page \
        --file compose.yaml \
        --file compose.page.yaml \
        "$@"
}

compose pull target
compose up --detach --wait --force-recreate target

actual_version=$(compose exec -T target php -r 'echo PHP_VERSION;')
if [ "$actual_version" != "$PHP_LAB_VERSION" ]; then
    printf '%s\n' \
        "ERROR: expected PHP $PHP_LAB_VERSION, received: $actual_version" >&2
    exit 1
fi

page=$(curl --fail --silent --show-error http://127.0.0.1:8088/index.php)
if [ "$page" != "php-lab" ]; then
    printf '%s\n' "ERROR: expected php-lab, received: $page" >&2
    exit 1
fi

printf '%s\n' \
    "PHP $PHP_LAB_VERSION lab is running at http://127.0.0.1:8088/" \
    'Run: python3 poc.py 127.0.0.1:8088' \
    'Stop it with ./stop-page.sh'
