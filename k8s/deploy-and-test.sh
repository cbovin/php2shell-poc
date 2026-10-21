#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
namespace=php-rce-lab

if kubectl get namespace "$namespace" >/dev/null 2>&1; then
    owner=$(kubectl get namespace "$namespace" \
        -o jsonpath='{.metadata.labels.app\.kubernetes\.io/part-of}')
    if [ "$owner" != "php-rce-lab" ]; then
        printf '%s\n' \
            "ERROR: namespace $namespace exists but is not owned by this lab" >&2
        exit 1
    fi
else
    kubectl apply -f "$repo_dir/k8s/namespace.yaml"
fi

kubectl --namespace "$namespace" create configmap php-rce-configuration \
    --from-file=php.ini="$repo_dir/target/php.ini" \
    --from-file=apache.conf="$repo_dir/target/apache.conf" \
    --from-file=index.php="$repo_dir/target/index.php" \
    --dry-run=client --output=yaml | kubectl apply -f -

kubectl --namespace "$namespace" create configmap php-rce-proof-code \
    --from-file=poc.py="$repo_dir/poc.py" \
    --dry-run=client --output=yaml | kubectl apply -f -

kubectl apply -f "$repo_dir/k8s/target.yaml"
kubectl --namespace "$namespace" rollout restart deployment/php-rce-target
kubectl --namespace "$namespace" rollout status deployment/php-rce-target \
    --timeout=3m

initial_page=$(kubectl --namespace "$namespace" exec \
    deployment/php-rce-target -- php -r \
    'echo file_get_contents("http://127.0.0.1/index.php");')
if [ "$initial_page" != "php-lab" ]; then
    printf '%s\n' "ERROR: expected php-lab, received: $initial_page" >&2
    exit 1
fi
printf '%s\n' "Initial page: $initial_page"

# The verification request touched the only Apache worker. Restart the Pod so
# the proof starts with a clean process and deterministic heap state.
kubectl --namespace "$namespace" rollout restart deployment/php-rce-target
kubectl --namespace "$namespace" rollout status deployment/php-rce-target \
    --timeout=3m

kubectl --namespace "$namespace" delete job php-rce-proof \
    --ignore-not-found --wait=true
kubectl apply -f "$repo_dir/k8s/proof-job.yaml"
kubectl --namespace "$namespace" wait --for=condition=complete \
    job/php-rce-proof --timeout=5m
kubectl --namespace "$namespace" logs job/php-rce-proof

final_page=$(kubectl --namespace "$namespace" exec \
    deployment/php-rce-target -- php -r \
    'echo file_get_contents("http://127.0.0.1/index.php");')
case "$final_page" in
    'php-lab: updated by the PoC'*) ;;
    *)
        printf '%s\n' "ERROR: proof page was not updated: $final_page" >&2
        exit 1
        ;;
esac

printf '%s\n' \
    'Kubernetes proof succeeded.' \
    "Namespace: $namespace" \
    "Final page:" \
    "$final_page"
