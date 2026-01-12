# FAQ

## Can I run multiple certificates on one machine?

Yes. Define multiple `[[profiles]]` entries. Each profile issues its own
certificate and uses a distinct identity derived from
`instance_id.service_name.hostname.domain`.

## Can I include URI SANs with ACME?

No. ACME only supports DNS/IP identifiers, so URI SANs are rejected by
step-ca in the ACME flow.

## Do I need EAB?

Only if your step-ca provisioner requires it. Otherwise, open enrollment works.

## Where should private keys live?

Use a directory with `0700` permissions. Keys should be `0600`.

## Can I rotate DB credentials?

Yes. Update your secret/env source and regenerate `secrets/config/ca.json`
using `scripts/update-ca-db-dsn.sh`.
