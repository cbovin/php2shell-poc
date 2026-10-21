# Attribution and licensing notice

## PHP security research

The official PHP advisories credit `lcfr-hax`, `sagitzadik-wiz`,
`tomash-areion`, and `amyb-oai` as reporters. They credit `arnaud-lb`,
`iluuu1994`, `bukka`, and `ndossche` for remediation development. Consult the
advisories for the authoritative and current credit records:

- https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w
- https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp

## Exploit-technique source

The heap-layout and ASLR-bypass technique from which `poc.py` was derived was
published at:

https://github.com/9bie/php2shell-bypass-aslr-exp

The referenced upstream revision is:

```text
4586f5cc120c82fd468b17469202bac629810ad9
```

Changes in this lab include an English-only implementation, fixed local target
and benign payload, Docker/Kubernetes isolation, four exact official-image
profiles, wider valid Linux mapping recognition, runtime image validation,
tests, and explanatory/mitigation documentation.

## Redistribution status

No license file was present in the upstream exploit repository at the revision
above. Absence of a license does not grant redistribution or relicensing rights.
This repository therefore intentionally does not declare an open-source license
for the derived PoC.

Before public redistribution, obtain permission from the relevant copyright
holder or replace the derived implementation with code whose provenance and
license have been independently reviewed. Adding a license only to this
repository would not resolve rights in upstream-derived material.
