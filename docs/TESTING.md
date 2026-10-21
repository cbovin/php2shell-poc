# Testing and reproduced results

## Test date and environments

The matrix below was reproduced on October 21, 2026. Docker tests used exact
official `linux/amd64` images. The Kubernetes test used MicroK8s v1.36.2 on an
amd64 Ubuntu 24.04.4 node with containerd 2.2.3.

| Version | Exact official image digest | Address mode | Result |
| --- | --- | --- | --- |
| 8.2.34 | `sha256:1650dcb528360aad05d6ed2f83cb403a2a39c31bd14552efd9a747b2207dea86` | Docker-assisted | `www-data` proof |
| 8.3.35 | `sha256:c59c808172ee3672cd334f8f2a5d7b1480a9d7273a368f412b8ee9b4ef418184` | HTTP-only | `www-data` proof |
| 8.4.26 | `sha256:60111400ff77bdc44fa79b4f072afe49a42abba71e0846ad496be4761dc9c11a` | HTTP-only | `www-data` proof |
| 8.5.11 | `sha256:47e6d8849049375e0d19e81f1b391ed88828d4653e0d1b00822185b66b564e8b` | HTTP-only | `www-data` proof |

All four Docker browser workflows and all four isolated `run.sh` workflows
succeeded. The 8.4.26 Kubernetes Job succeeded repeatedly on a freshly rolled
target Pod.

## Non-destructive checks

Run unit tests, Python compilation, shell syntax checks, Compose rendering, and
repository whitespace checks:

```bash
./tests/static.sh
```

These checks do not send the exploit sequence.

## Isolated Docker integration

Run one profile:

```bash
./run.sh 8.4.26
```

Run every supported profile:

```bash
./tests/integration.sh
```

The integration runner verifies this sequence:

1. pull the immutable target and runner images;
2. start the target on a Docker-internal network;
3. require the initial HTTP response to equal `php-lab`;
4. restart Apache to normalize the worker state;
5. run the fixed-target proof;
6. require and print the updated page;
7. remove the test containers, volume, and network.

The persistent browser workflow uses a different Compose project and binds
only `127.0.0.1:8088`.

## Kubernetes integration

With a disposable or explicitly authorized current `kubectl` context:

```bash
./k8s/deploy-and-test.sh
```

The script refuses to reuse an existing `php-rce-lab` namespace unless that
namespace carries this lab's ownership label. It verifies the initial page,
rolls the target, recreates the proof Job, waits for completion, prints the Job
log, and independently verifies the final page.

The target remains for inspection because deleting a namespace is a destructive
operation. Remove it explicitly when finished:

```bash
kubectl delete namespace php-rce-lab
```

## Expected target behavior

The final crafted request can crash an Apache child after the command is
invoked. This is expected in this proof. The prefork parent creates a replacement
worker, and that replacement serves the updated page. A container or Pod restart
is not required for a successful run.

## What was not tested

- Native Ubuntu/Debian/RHEL PHP packages.
- PHP-FPM, FrankenPHP, LSAPI, or CGI builds.
- ARM or other non-amd64 architectures.
- Arbitrary extension sets or production application configurations.
- Fixed releases as exploit targets.

Do not turn the PoC into a production scanner. A negative result has no useful
assurance value because the exploit is build- and layout-specific.
