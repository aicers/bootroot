# Bootroot Design Philosophy

## Primary Goal — mTLS Certificate Rotation

Bootroot is a system that issues and rotates certificates when (daemon or
Docker) services authenticate each other via mTLS. The security emphasis is on
**rotation**: whereas renewal responds to expiration, rotation replaces
certificates periodically regardless of whether they have expired. There are
two ways to implement rotation. One is to replace certificates on a fixed
schedule regardless of expiration. The other is to set a short validity period
and renew before expiration, so that periodic replacement happens as a natural
consequence. Bootroot uses the latter approach.

## Secondary Goal — Automation

Automating the entire process of initial issuance and periodic rotation as
safely as possible is also an important goal. Without automation, the process
is not only inconvenient but also prone to human-introduced security gaps.
The `bootroot-agent` daemon automatically handles obtaining new certificates
from the CA.

## Full Automation Is Not Possible for Security Reasons

Complete automation is impossible from a security standpoint. Recklessly
automating procedures such as initial trust establishment can itself become a
security vulnerability. Some steps in Bootroot therefore require manual
intervention, and Bootroot is designed to minimize those manual steps.

## Not Automated (1) — CA Key Renewal

Bootroot does not provide a feature to change the CA's private/public key pair
after initial generation. CA key rotation is not supported; replacing the CA
keys currently requires a full re-initialization. (A dedicated CA key
replacement feature is planned for the future.)

## Derived Goal for Certificate Rotation Automation — Secret Management

The ACME protocol used by Bootroot requires the CA to authenticate the
requester via EAB kid/hmac before issuing or renewing a certificate. EAB
kid/hmac functions like a username and password: `bootroot-agent` must deliver
these values to the CA, and they must be managed securely throughout the
automated process. A secrets manager is therefore required, and Bootroot uses
OpenBao. (Values like passwords that must be kept safe are called secrets.)

## Tertiary Goal — Secret Rotation

As with certificates, the security emphasis for secrets is on rotation. The
secrets manager only stores secrets securely; automated rotation is performed
by Bootroot.

## Not Automated (2) — OpenBao Unseal Keys and SecretID

Secrets required to use the secrets manager itself must inevitably be managed
manually by the operator.

OpenBao requires unseal keys and a root token. Unseal keys are needed when
starting OpenBao, and the root token is needed for every interaction with
OpenBao.

**Unseal keys.** These are only needed when starting OpenBao, so the operator
must remember them separately and enter them manually. (A development
convenience feature is provided that writes unseal keys to a file and reads
them when OpenBao starts.)

**Root token.** Bootroot uses the root token only during initialization; it is
not required for day-to-day operations. Instead, Bootroot defaults to AppRole
with SecretID authentication. AppRole and SecretID are, like EAB, an
authentication mechanism for OpenBao. The critical security concern is
SecretID rotation. Bootroot does not automate SecretID rotation because, when
SecretID must be delivered to a different machine, additional management
infrastructure would be needed to do so securely.

## Automatic vs. Manual Secret Rotation

SecretID rotation and delivery must be performed by the operator using
Bootroot CLI (`bootroot` & `bootroot-remote`) commands. All other secrets are
rotated and delivered automatically by Bootroot. SecretID grants access to
OpenBao itself, but the remaining secrets can be retrieved by connecting to
OpenBao, which makes their rotation automatable. OpenBao Agent handles
retrieving secrets from OpenBao.

## Not Automated (3) — Initial CA Trust

The initial trust problem exists not only on the secrets-manager side but also
on the certificate issuance/renewal side. When `bootroot-agent` communicates
with the CA, it must verify that the CA is legitimate, which requires
distributing the CA certificate in advance. Doing this manually is
inconvenient, and doing it automatically requires a separate mechanism to
secure the distribution. Fortunately, Bootroot's default environment is one
where the operator controls both the CA and `bootroot-agent` when services are
first installed, so skipping CA verification during initial issuance is
acceptable. Because the CA certificate is obtained during this initial process,
CA verification is guaranteed for all subsequent automated certificate
rotations.

## Not Automated (4) — Installation and Operations

There are aspects of installation and operations that fall outside Bootroot's
automation scope:

- **Installation**: The operator must install the Bootroot CLI and per-service
  OpenBao Agent and `bootroot-agent` manually. (Infrastructure components
  including the CA and their OpenBao Agents are installed automatically during
  `bootroot infra up`.)
- **Process management**: The operator must configure and verify systemd or
  Docker restart settings so that manually installed OpenBao Agents and
  `bootroot-agent` instances keep running.
- **Rotation scheduling**: Bootroot provides the rotation command
  (`bootroot rotate`), but scheduling its periodic execution (cron, systemd
  timer, etc.) is the operator's responsibility.
