# Mitigations

## Required remediation

Updating PHP is the only complete mitigation identified by both official
advisories. Upgrade each maintained branch to at least:

| Branch | First patched release |
| --- | --- |
| PHP 8.2 | 8.2.35 |
| PHP 8.3 | 8.3.36 |
| PHP 8.4 | 8.4.27 |
| PHP 8.5 | 8.5.12 |

Older unsupported branches should not be treated as unaffected merely because
they are absent from this maintained-branch table. Move them to a supported
branch that contains both fixes.

After updating, restart every Apache process, PHP-FPM master and child, pod,
container, or other long-lived PHP worker. A package installed on disk does not
remove stale vulnerable workers that are still serving requests.

Confirm the version used by the web SAPI, not only an unrelated CLI binary. In
containers, inspect the running pod/container and its immutable image digest.
For native installations, verify the package provider's security notice if it
backports fixes without changing the upstream-looking version string.

## Temporary risk reductions

These measures come from the official advisory guidance. They are incomplete
and should be used only while an upgrade is being completed.

### Disable session upload progress

If the application does not need this feature, set it administratively in
startup configuration:

```ini
session.upload_progress.enabled = Off
```

Restart every worker after the change. This breaks the demonstrated early
session producer/consumer path, but it does not address other stale global
state families covered by CVE-2026-109619.

Do not rely on per-request application code to change this setting: vulnerable
processing can happen before the target script runs.

### OOM-specific workaround

For CVE-2026-109618, the official advisory identifies an administratively
enforced `memory_limit=-1` as the primary configuration workaround when patching
is temporarily impossible:

```ini
memory_limit = -1
```

This is counterintuitive and **not a complete mitigation**. It removes the
predictable PHP per-request OOM used by the confirmed exploit, but an underlying
allocation can still fail. It also removes an important application-level
resource guard and can increase denial-of-service impact. Use it only with
independent frontend request limits, operating-system/container memory controls,
monitoring, and an urgent upgrade plan. Restart all workers and ensure no pool,
directory, `.user.ini`, or application setting restores a finite limit.

The official advisory warns against using `RLIMIT_AS` or `RLIMIT_DATA` as a
substitute because they can make `mmap()` fail and reach the vulnerable path.
A cgroup/container memory ceiling can reduce host impact but is not itself a
complete vulnerability mitigation.

### PHP 8.5 fatal-backtrace path

For an unpatched PHP 8.5 installation, the stale-state advisory recommends:

```ini
fatal_error_backtraces = 0
```

Restart all workers. This removes the producer used by one confirmed PHP 8.5
case but does not cover session state or other extension/global state.

### Reduce reachable triggers

- If multipart forms and file uploads are not needed, reject their content
  types at the reverse proxy before PHP receives the body.
- Enforce decoded body size and request time limits at the frontend, not only
  PHP's declared `Content-Length` checks.
- Bound input variables, nesting depth, multipart parts, per-part headers, and
  upload counts.
- Remove attacker-reachable fatal errors, timeouts, failing callbacks, and
  warnings from upload, import, shutdown, destructor, serialization, output
  handler, plugin, and extension paths.
- Prefer valid startup configuration over per-directory or per-request INI
  overrides that can emit diagnostics before normal initialization.
- For FPM, `pm.max_requests=1` can reduce cross-request state reuse when the
  performance cost is acceptable. It is risk reduction, not a fix.

## Audit guidance

During an isolated audit, enable functional error logging and review PHP,
Apache/FPM, reverse-proxy, and service logs for:

- fatal, parse, uncaught, and maximum-execution-time errors;
- warnings or deprecations before target scripts start;
- diagnostics during extension or server cleanup;
- failures restricted to attacker-controlled routes, files, content types,
  callbacks, or plugin options.

Absence of log entries is not proof of safety: a failure may precede logging,
and tests rarely cover every application state.

## Deployment checklist

1. Inventory the actual PHP version, SAPI, package source, architecture, and
   every independently running worker pool.
2. Upgrade to the fixed release for the branch, or to a newer maintained branch.
3. Rebuild images without a stale layer or floating cached tag.
4. Roll every pod/container/worker; do not leave old replicas serving traffic.
5. Verify the running version and image digest from inside each workload.
6. Remove temporary workarounds that are no longer operationally appropriate.
7. Keep session upload progress disabled if unused, and retain conservative
   frontend request controls as defense in depth.

Do not use failure of this build-specific PoC as a patch-verification method.
Version/package inventory and vendor security status are the reliable controls.
