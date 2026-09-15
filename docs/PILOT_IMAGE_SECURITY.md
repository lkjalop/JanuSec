# Pilot image security — 2026-09-15

The isolated image now applies Debian security updates during build, updates
Python packaging dependencies, checks dependency consistency, then removes pip
and ensurepip (including their bundled executable dependencies). Runtime package
installation is intentionally unavailable: rebuild the image to change dependencies.
Setuid/setgid executable bits are removed. The profile also uses UID 10001,
no capabilities, no-new-privileges and a read-only root filesystem.

Trivy 0.74.0 scanned the actual Docker image, including all severities and unfixed
findings. The initial image had 187 package findings: 3 critical, 55 high, 67 medium,
61 low and 1 unknown. The patched image has 150: **0 critical, 44 high, 48 medium,
57 low and 1 unknown**. No remaining high finding has a listed fix in this scan.
These counts are package findings; one vulnerability can affect several packages.

The remaining high IDs are CVE-2025-69720, CVE-2026-16742, CVE-2026-54369,
CVE-2026-76642, CVE-2026-78408, CVE-2026-78409, CVE-2026-78410 and CVE-2026-9538.
They require deployment-specific applicability review and future vendor updates.
The runtime restrictions reduce exposure; they do not establish that these
vulnerabilities are fixed or unreachable. Debian documents the
[util-linux finding](https://security-tracker.debian.org/tracker/CVE-2026-76642)
and the [deferred Archive::Tar fix](https://security-tracker.debian.org/tracker/CVE-2026-9538).

`Pilot image security` CI builds the actual image and preserves the full JSON scan.
Its gate rejects every critical finding and every high finding with a listed fix.
Unfixed high findings remain visible in the summary and artifact. This scoped gate
does **not** grant production approval or supersede the other release holds.
Weekly scans detect changes in vendor advisories; each rebuilt image needs its own
scan because security updates and dependency resolution can change its contents.

The locally scanned image ID is
`sha256:769c56873df4de03019ec499514d8b5e543e0ac0d4a84edeef9e99b86888e19e`.
It passed existing evidence/case/historical-receipt verification, named-role and
revoked-key checks, and real Chromium clickthrough of five tabs, evidence detail,
authenticated export, mobile layout and reload, with zero observed JS/HTTP errors.
No setuid/setgid files were returned by a runtime filesystem check.

This is local isolated validation. Retained GitHub history cleanup, real-source
continuity, customer TLS, a hard persistent-volume quota, sustained ingestion and
off-host recovery remain open. See [access and resource limits](PILOT_ACCESS_AND_RESOURCE_BOUNDARY.md).
