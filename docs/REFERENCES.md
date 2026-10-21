# References

## Primary vulnerability sources

- PHP security advisory: [CVE-2026-109618 / GHSA-w8hw-w9fx-j79w: RCE via OOM corruption](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- PHP security advisory: [CVE-2026-109619 / GHSA-6wmf-4rv5-p3rp: RCE via stale global state](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- PHP manual: [Session upload progress](https://www.php.net/manual/en/session.upload-progress.php)
- PHP manual: [`memory_limit` and core INI directives](https://www.php.net/manual/en/ini.core.php#ini.memory-limit)

## Reproduction and packaging sources

- Original public exploit-technique repository: [`9bie/php2shell-bypass-aslr-exp`](https://github.com/9bie/php2shell-bypass-aslr-exp)
- Official PHP Docker image source: [`docker-library/php`](https://github.com/docker-library/php)
- Kubernetes documentation: [Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/)

The official PHP advisories are the authority for affected ranges, remediation,
SAPI analysis, impact, and credited researchers. This repository documents only
the exact environments it independently reproduced.
