# FAQ

## Can I run multiple certificates on one machine?

Yes. Define multiple `[[profiles]]` entries. Each profile issues its own
certificate and can use distinct domains and paths.

## Can I use SPIFFE without DNS names?

Not today. ACME HTTP-01 requires `domains`, and those values are always added
as DNS SANs. `uri_san_enabled = true` only adds a SPIFFE URI; it does not
remove DNS SANs.

## Do I need EAB?

Only if your step-ca provisioner requires it. Otherwise, open enrollment works.

## Where should private keys live?

Use a directory with `0700` permissions. Keys should be `0600`.

## Can I rotate DB credentials?

Yes. Update your secret/env source and regenerate `secrets/config/ca.json`
using `scripts/update-ca-db-dsn.sh`.
