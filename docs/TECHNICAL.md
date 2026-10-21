# Technical explanation

## Scope

This lab reproduces an application-independent Apache `mod_php` path involving
multipart parsing, session upload progress, memory exhaustion, stale
request-owned state, heap disclosure, and a controlled indirect call. It uses
the two related PHP advisories together; it is not intended to isolate each CVE
as a separate minimal test case.

The official descriptions are authoritative:

- CVE-2026-109618 covers unsafe handling of out-of-memory exits. PHP's former
  `longjmp()` path could abandon contexts while request memory was temporarily
  invalid, after which request shutdown processed that state.
- CVE-2026-109619 covers request-owned data retained in worker-global state.
  A later request handled by the same worker could consume a stale pointer
  before normal initialization reset it.

Both can cross security boundaries before application code begins. The lab's
`index.php` is intentionally passive and only displays the final proof file.

## Request sequence

```text
multipart request A
  -> session upload progress publishes request-owned state
  -> controlled memory exhaustion interrupts cleanup
  -> request heap is released while stale state survives

multipart request B on the same Apache worker
  -> attacker-shaped allocations reuse selected heap slots
  -> early session handling consumes stale state
  -> disclosure or controlled object interpretation occurs

repeat with calibrated layouts
  -> disclose Zend heap base
  -> disclose libphp base
  -> place a fake HashTable/call structure
  -> invoke the fixed system("id>/out/p1") proof
```

The lab configures one prefork worker to make the same-worker requirement
deterministic. Multiple production workers do not remove the vulnerability;
they change which request reaches the affected worker and therefore reduce
per-attempt reliability.

## Proof stages

### 1. Worker normalization

`rotate_worker()` deliberately terminates the current Apache child and waits
for the prefork parent to replace it. Each major stage then starts from a clean,
repeatable process layout. A worker crash during the final stage is expected;
Apache replaces it and the replacement serves the proof page.

### 2. Zend heap disclosure

The first layout uses session upload-progress processing, a controlled OOM, and
attacker-sized multipart fields. The next request places a forged string-like
layout where stale state will interpret it. Cookie serialization returns bytes
from adjacent memory. The PoC searches that disclosure for repeated Linux mmap
pointers and aligns the dominant candidate to PHP's 2 MiB Zend heap region.

### 3. `libphp.so` disclosure

A second allocation layout shapes nested PHP arrays so the stale value exposes
a destructor pointer in a session cookie. The profile subtracts the exact
`zval_ptr_dtor` symbol offset for the pinned binary, yielding the module load
base. Page alignment and pointer-range checks reject implausible disclosures.

### 4. Controlled call

The final layout places a fake HashTable and related zval/function data at a
calibrated heap address. A short carrier value redirects the stale reference to
that structure. The structure contains the calculated address of `zif_system`
and only this fixed command:

```text
id>/out/p1
```

The command writes the Apache worker identity to an isolated volume. The page
is mounted read-only and merely displays `/out/p1`; therefore the visible
change proves execution without modifying the application source.

## ASLR handling by profile

PHP 8.3.35, 8.4.26, and 8.5.11 use both HTTP disclosures described above.
Those profiles do not read the Docker API or target process maps.

PHP 8.2.34 clears `send_cookie` after the producing request, so the same
in-band cookie disclosure is unavailable. The local-only 8.2 workflow instead:

1. identifies the dedicated Compose target;
2. verifies its runtime PHP version and exact image digest;
3. reads `/proc/1/maps` inside that owned container;
4. resolves the zero-offset `libphp.so` mapping and the 2 MiB Zend heap region;
5. passes only those two addresses to the restricted proof runner.

Consequently, the 8.2 profile demonstrates the corruption and command-call
primitive but not a remote ASLR bypass.

## Why profiles are exact-build specific

The proof contains offsets for `zif_system`, `zval_ptr_dtor`, and a stable
attacker-controlled heap location. They depend on the compiled binary and heap
geometry. A package with the same PHP version can differ because of compiler
flags, distribution patches, linked libraries, extensions, SAPI, architecture,
and allocator behavior.

For this reason, the allowlist identifies exact official Docker manifests and
the Compose file forces `linux/amd64`. The PoC must not be described as working
against arbitrary native Ubuntu packages or arbitrary PHP installations.

## SAPI interpretation

This repository validates Apache `mod_php` only. The official advisories
discuss additional SAPI behavior, including confirmed or conditional FPM paths,
but those paths can require different producers, consumers, application
behavior, and layouts. Success here is not evidence that this exact script will
work against FPM, FrankenPHP, LSAPI, or another server integration.

## What success and failure mean

A successful run proves unauthenticated command execution as the web worker in
the selected exact lab build and configuration.

A failed run does not prove that a PHP deployment is patched or safe. Worker
scheduling, build differences, frontend normalization, configuration, memory
pressure, and heap noise can all break this build-specific PoC while the
underlying PHP version remains affected. Use package inventory and the official
fixed-version thresholds for remediation decisions.
