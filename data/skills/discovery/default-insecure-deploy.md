# Skill: Validate authentication boundaries in quick-start deployments

## Metadata
- **Category**: discovery
- **Language**: any
- **Stacks**: docker, compose, helm, kubernetes
- **Signals**: docker-compose.yml, docker-compose.yaml, dockerfile, values.yaml, .env
- **Scope**: deployment configuration; no repository-specific result is implied

## When to use
Review a project's documented quick-start when it exposes a service outside the
intended trust boundary. A published port or missing configuration key is a lead,
not a confirmed authentication bypass or an automatic CWE assignment.

## Prerequisites
- Pin the repository revision, image digest and exact documented configuration.
- Establish listener addresses, network reachability, credential initialization
  and the operations available to each role in that deployment.
- Separate a local test-only setup from a supported deployment reachable by an
  untrusted actor. Read the project's intended security boundary.

## Discovery vectors (up to ten)
- Read the quick-start README, compose file, Helm values and Dockerfile for a
  published port paired with a missing or empty credential.
- Check for default or empty admin passwords, `trust`-style auth, and accounts
  created without a secret.
- Compare the bind address (loopback vs `0.0.0.0`) against the documented
  intended reachability.
- Trace whether the documented setup enables an authenticator but leaves an
  anonymous or default path open.
- Diff the "getting started" configuration against the "production" or
  "hardening" guide to see what the quick-start omits.
- Inspect environment-variable defaults that disable auth for convenience.
- Look for management, metrics, or debug endpoints exposed by the default
  configuration.
- Check whether TLS or client verification is disabled by default.
- Distinguish a per-target protocol and its own access checks; evidence from a
  database does not establish the behavior of a message broker.
- Confirm the actor: is the exposed operation reachable by an untrusted network
  caller, or only by a local operator who already owns the host?

## Cross-language and stack examples
- Databases: an image documented with an empty root password on a published port (MySQL/Mongo/Redis quick-starts).
- Message brokers: a default config that sets a port and omits an authentication block (Kafka/RabbitMQ/MQTT).
- Web dashboards and admin UIs: bound to all interfaces with a default or blank admin password.
- Key-value, search, and analytics services: a quick-start that disables auth for convenience (Elastic/OpenSearch/etcd).
- Orchestration/compose: docker-compose or Helm values exposing an internal admin port or a `0.0.0.0` bind.
- IaC defaults: a Terraform/Ansible module whose default security group or auth toggle is permissive.
- Contrast (safe): a shipped default that requires a password and binds to loopback - the negative control.

## How to validate
Use an authorized isolated lab and a harmless, reversible operation that measures
the claimed privilege. Compare no credentials, invalid credentials and the
intended authorized role. Record the exact target, configuration, caller,
request and observed state change; require signed target-bound proof before
publishing a finding. Startup success or a listening socket is not impact.

## Counterexamples and limits
Loopback-only binding, enforced authentication, a lower-privilege operation or
an explicitly trusted local setup can refute the claimed remote boundary.
An unavailable lab is inconclusive. Classify only the proven configuration
failure; do not describe it as a code authentication bypass without separate
evidence that a protected code path accepts an unauthorized caller.

Evidence bar: a match here is a lead, not a finding - confirm with a bounded oracle (the shipped default accepting an unauthenticated privileged action), a passing negative control (the hardened, non-default config refuses the same action), and signed target-bound proof on the shipped artifact.
