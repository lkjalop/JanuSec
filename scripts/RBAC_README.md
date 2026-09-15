RBAC CLI
========

This repository includes a lightweight RBAC store backed by `data/roles.json`.

You can manage roles using the CLI script:

  python scripts/rbac_manage.py list
  python scripts/rbac_manage.py assign <api_key> <role>
  python scripts/rbac_manage.py revoke <api_key> <role>

The CLI uses `src.security.rbac` helpers which persist changes to disk. You can
override the file location with the `ROLE_STORE_PATH` environment variable.

Note: For safety the API endpoints still accept the legacy `ADMIN_API_KEY` via
the `X-Admin-Key` header. The RBAC store enables role-based checks via the
`X-Api-Key` header.
