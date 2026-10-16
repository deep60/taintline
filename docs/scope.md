# Writing SCOPE.yaml

Copy `SCOPE.example.yaml` to `SCOPE.yaml`. All fields are checked on load.

- `name`, `authorized_by`: required. `authorized_by` must name who gave permission.
- `servers`: explicit hostnames (with port) or stdio server names. No wildcards.
- `tools`: optional allow-list. Omit or null for every tool on in-scope servers.
- `fuzz`: must be `true` for any active probing. Default false.

Everything not listed is refused (`scope.Gate` raises `OutOfScope`). Phase 1 code must call
the gate before every connection and every probe.
