---
title: "about"
url: "/about/"
summary: "about"
ShowReadingTime: false
ShowToc: false
ShowBreadCrumbs: false
hidemeta: true
---

Sysadmin + security researcher based in the Netherlands. Day job in healthcare IT — identity, auth, endpoint, the usual mess.

## Focus

- Identity & auth (Keycloak, Entra, OIDC/SAML flows)
- Healthcare IT security (NEN 7510, AVG/GDPR, vendor risk)
- Responsible disclosure

## Disclosures

- **Keycloak policy-enforcer — authorization bypass** (CVE-2026-9800, GHSA-f5p5-6xmx-p252) — authenticated authz bypass via substring URI match, CVSS 8.1, fixed in 26.6.4 / 26.0.10. [Writeup](/posts/keycloak-policy-enforcer-uri-bypass/).
- **libvncclient — Tight decoder heap overflow** (CVE-2026-50538, GHSA-v9pm-47h4-jcq8) — pre-auth OOB write, CVSS 8.8, fixed in `6724d69`. [Writeup](/posts/libvncclient-tight-oob-write/).

_More pending coordinated disclosure._

## Contact

- Email: contact@baslevering.com
- PGP: [key](/pgp.txt) (fingerprint pending)
- Security disclosures: see [/.well-known/security.txt](/.well-known/security.txt)
