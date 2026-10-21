# php2shell-poc

Reproducible, local-only research lab for the related PHP request-lifecycle
vulnerabilities:

- [CVE-2026-109618 / GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w): RCE via OOM corruption.
- [CVE-2026-109619 / GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp): RCE via stale global state.

Both official advisories are rated critical, with CVSS 4.0 score 9.2. This
repository reproduces a combined session-upload-progress/OOM path against exact
official Apache Docker images. It is not a scanner and does not accept an
arbitrary host or command.

> **Research use only.** Run this code only in the included isolated lab or on
> systems you own and have explicitly designated for testing. Never point it at
> a production PHP or REDCap deployment.

## Result

The proof executes one fixed command as Apache's unprivileged worker:

```text
id>/out/p1
```

The read-only PHP page displays the resulting proof file:

```text
php-lab: updated by the PoC
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

No web source file is modified by the exploit.

## Affected and fixed versions

The two PHP advisories publish the same branch thresholds:

| PHP branch | Advisory range | First patched release | Exact vulnerable image tested here |
| --- | --- | --- | --- |
| 8.2 | `< 8.2.35` | 8.2.35 | `php:8.2.34-apache` |
| 8.3 | `< 8.3.36` | 8.3.36 | `php:8.3.35-apache` |
| 8.4 | `< 8.4.27` | 8.4.27 | `php:8.4.26-apache` |
| 8.5 | `< 8.5.12` | 8.5.12 | `php:8.5.11-apache` |

These are PHP core issues, not REDCap-specific vulnerabilities. Actual
reachability and reliability depend on the SAPI, worker lifecycle, application,
extensions, frontend behavior, configuration, binary build, and heap layout.
Versions and branches not listed in the lab matrix were not tested here.
Older unsupported branches are not safe by omission; migrate them to a
maintained branch containing the fixes.

## Reproduced matrix

| Exact image | Address-resolution mode | Docker | Kubernetes |
| --- | --- | --- | --- |
| `php:8.2.34-apache` | Docker-assisted local lookup | Verified | Not implemented |
| `php:8.3.35-apache` | HTTP-only leak chain | Verified | Not implemented |
| `php:8.4.26-apache` | HTTP-only leak chain | Verified | Verified |
| `php:8.5.11-apache` | HTTP-only leak chain | Verified | Not implemented |

The profiles are specific to the pinned `linux/amd64` builds. Native Ubuntu
PHP packages, FPM images, ARM builds, and other vendor binaries have different
symbol offsets and may have different allocator behavior; this PoC is not
calibrated for them.

PHP 8.2.34 also needs an important qualification: it clears the cookie state
used by the in-band address leak in the newer profiles. For that version, the
local Docker workflow validates the exact image and reads two ASLR bases from
the owned container's `/proc/1/maps`. It then exercises the same corruption and
fixed execution stage. This proves the primitive in the lab, but it is not an
ASLR-independent remote proof for PHP 8.2.34.

## Quick start: browser workflow

Requirements: Docker Engine, Docker Compose v2, Python 3, and `curl` on an
x86-64 Linux host. Start one exact version; 8.4.26 is the default:

```bash
./start-page.sh 8.4.26
```

Open <http://127.0.0.1:8088/> and confirm that it displays:

```text
php-lab
```

Run the fixed proof from another terminal:

```bash
python3 poc.py 127.0.0.1:8088
```

Refresh the browser to see the updated page. Stop and remove the lab afterward:

```bash
./stop-page.sh
```

The same commands work with `8.2.34`, `8.3.35`, or `8.5.11` as the argument to
`start-page.sh`. The PoC auto-detects the exact PHP version from the local
target and selects its matching profile.

## One-command Docker tests

`run.sh` creates an internal Docker network, verifies the initial page, runs
the proof, prints the result, and removes its containers, network, and volume:

```bash
./run.sh 8.2.34
./run.sh 8.3.35
./run.sh 8.4.26
./run.sh 8.5.11
```

Run the complete supported matrix with:

```bash
./tests/integration.sh
```

## Kubernetes test

The Kubernetes workflow currently covers the HTTP-only 8.4.26 profile. It
creates a dedicated `php-rce-lab` namespace, a ClusterIP Service with no
NodePort/LoadBalancer/Ingress, a target ingress policy, and a restricted proof
Job without a service-account token:

```bash
./k8s/deploy-and-test.sh
```

Inspect the result:

```bash
kubectl -n php-rce-lab get deployment,pod,service,job,networkpolicy
kubectl -n php-rce-lab logs job/php-rce-proof
```

Remove only the lab namespace when finished:

```bash
kubectl delete namespace php-rce-lab
```

This workflow was verified on MicroK8s v1.36.2 on an amd64 Ubuntu 24.04.4
node.

## Mitigation summary

Upgrade is the only complete mitigation. Use at least PHP 8.2.35, 8.3.36,
8.4.27, or 8.5.12 for the corresponding maintained branch, and restart every
PHP/Apache/FPM worker after upgrading.

If an immediate upgrade is impossible, the official advisories describe
temporary risk reductions, including administratively disabling session upload
progress, special handling of PHP's memory limit, request-size enforcement,
and, for one PHP 8.5 path, disabling fatal error backtraces. None is a complete
replacement for patching, and some carry operational risks. See
[Mitigations](docs/MITIGATIONS.md) before applying any workaround.

## Safety properties

- Accepted targets are hard-coded to `target:80`, `127.0.0.1:8088`, and
  `localhost:8088`.
- The command is fixed in source and cannot be supplied on the command line.
- Browser mode binds only to loopback; automatic mode publishes no host port.
- The Docker runner has no Docker socket, drops all capabilities, and uses a
  read-only root filesystem.
- Kubernetes uses a ClusterIP-only Service and restricts target ingress to the
  labeled proof Job.
- Images are pinned by immutable digest and runtime versions are checked.
- The vulnerable PHP settings are confined to this lab. Do not copy them into
  a production deployment.

## Documentation

- [Technical explanation](docs/TECHNICAL.md)
- [Mitigations and deployment checklist](docs/MITIGATIONS.md)
- [Test method, exact image pins, and results](docs/TESTING.md)
- [Primary references](docs/REFERENCES.md)
- [Pre-publication checklist](docs/PUBLICATION_CHECKLIST.md)
- [Security policy](SECURITY.md)
- [Attribution and licensing notice](NOTICE.md)

## Repository layout

| Path | Purpose |
| --- | --- |
| `poc.py` | Version-profiled, local-target-only proof |
| `versions.sh` | Supported versions and immutable image references |
| `compose.yaml` | Isolated target and restricted proof runner |
| `start-page.sh`, `stop-page.sh` | Persistent loopback browser workflow |
| `run.sh` | One-version Docker integration test with cleanup |
| `tests/` | Non-destructive unit/static checks and full lab matrix runner |
| `k8s/` | ClusterIP-only 8.4.26 target and proof Job |
| `target/` | Minimal Apache, PHP, and read-only page configuration |

## Attribution and redistribution

The official advisory credits and upstream exploit-technique attribution are
recorded in [NOTICE.md](NOTICE.md). The exploit implementation was derived from
an upstream repository that did not contain a license at the referenced
revision. Do not publish or redistribute the derived PoC until you have
confirmed permission or otherwise resolved its copyright status. No license is
added here because doing so would not cure missing upstream permission.
