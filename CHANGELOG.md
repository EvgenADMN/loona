# Changelog

Versions follow [Semantic Versioning](https://semver.org/). The number lives in
`core/version.py`; the Dockerfile label and the newest heading here follow it.

## 1.0.0 - 2026-10-15

The first release.

### Ansible
- Inventory: hosts, nested host groups, group and host variables; a group is a run target.
- Playbooks in two interchangeable editors: a graphical task builder with forms for every
  installed module (from `ansible-doc`) and raw YAML.
- Ansible projects with roles, templates and files, kept in Loona or pulled from Git;
  `requirements.yml` for roles and collections.
- Preview in check mode with per-host diffs, then apply exactly what was previewed.
- Launch templates with survey forms, ad-hoc commands, schedules, drift checks.
- Host facts kept from every run and searchable (`os:ubuntu ram>=8`).

### OpenTofu
- Projects with plan and apply, Loona as the state backend.
- Machines OpenTofu creates join the inventory and get Loona's SSH key.
- Self-service catalog: a form, a plan, an approval, a host.

### Workflows
- Steps joined by success, failure and always arrows: OpenTofu, playbooks, approvals,
  messages. Started by hand, by API, by trigger URL or on a schedule.
- OpenTofu outputs handed to later playbook steps.

### Access and security
- Teams with Viewer, Operator and Admin roles on host groups; writing playbooks and
  OpenTofu code are separate global rights.
- Sign-in with local accounts, LDAP / Active Directory, OIDC or SAML; one-time codes (TOTP);
  wrong passwords and codes slow further attempts down.
- Two-person rule and maintenance windows for applying changes.
- One Ed25519 key per host, pinned SSH host keys.
- Credentials and secrets encrypted at rest; secrets from Loona, Ansible Vault or
  HashiCorp Vault, masked in run logs.
- Audit log of administrative changes.
- HTTPS behind a reverse proxy: `LOONA_HTTPS`, `LOONA_TRUST_PROXY`, `LOONA_HSTS_SECONDS`.
- Content-Security-Policy without inline scripts.

### Operations
- One container image with Ansible and OpenTofu; compose file with PostgreSQL and Redis.
- Remote executors: agents in closed networks that connect out to Loona.
- REST API with personal tokens and an OpenAPI schema; trigger URLs for CI.
- Notifications by email, Telegram and webhook.
- English and Russian interface, chosen per person.
