# Publication checklist

## Required before making the repository public

- [ ] Resolve the upstream exploit code's missing-license status. See
      [`NOTICE.md`](../NOTICE.md). Do not assume that public source code is
      automatically open source.
- [ ] Re-check both official PHP advisories for corrections to affected ranges,
      mitigation text, credits, severity, or identifiers.
- [ ] Run `./tests/static.sh` from a clean checkout.
- [ ] Run `./tests/integration.sh` on an isolated x86-64 Docker host.
- [ ] If documenting Kubernetes, run `./k8s/deploy-and-test.sh` on a disposable
      or explicitly authorized cluster and then delete `php-rce-lab`.
- [ ] Confirm `git status` is clean and inspect every tracked file for tokens,
      passwords, private IP addresses, usernames, kubeconfigs, screenshots, and
      environment-specific identifiers.
- [ ] Confirm no vulnerable container, Pod, Service, volume, or namespace is
      exposed or left running after evidence collection.
- [ ] Preserve the official advisory credits and upstream technique attribution.
- [ ] State clearly that PHP 8.2.34 uses Docker-assisted address lookup and is
      not an HTTP-only remote ASLR-bypass demonstration.
- [ ] State clearly that native distribution packages, FPM, ARM, and arbitrary
      builds were not validated by this PoC.
- [ ] Avoid presenting PoC failure as evidence that a deployment is patched.

## Suggested release notes

Include:

- both CVE and GHSA identifiers;
- the publication/test date;
- exact tested image digests;
- supported architecture and SAPI;
- the fixed benign command and local-only target allowlist;
- the first patched versions;
- the explicit statement that upgrading is the only complete mitigation;
- links to `TECHNICAL.md`, `MITIGATIONS.md`, and `TESTING.md`.

Do not include live credentials, private infrastructure details, or claims that
were not reproduced and supported by the official advisories.
