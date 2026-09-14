# Skill: Fail-Open Native Authn/Authz (brokers and databases)

## Metadata
- **Category**: discovery
- **Language**: c/cpp ruby java go multi-protocol
- **Stacks**: broker, database, kafka, nats, amqp, mqtt, activemq, rabbitmq, mysql, postgres, mongodb
- **Signals**: sasl, anonymousauthenticator, shouldpass, allowall, librdkafka, amqplib, pika, sarama
- **Unique vs**: envoy-ext-authz-fail-open (xDS HTTP filters) and go-reverse-proxy-dashboard-auth (frp-style token). This skill is a server that ships an authenticator plugin and defaults it off, or an authorizer that returns allow.

## Doctrine
Message queues and databases often ship an authenticator AND default it off.
Enabling a basic authenticator without disallowing the anonymous credential is not
"auth on". An authorizer that returns allow while ignoring the authentication
result is a fail-open control plane, not defense-in-depth.

## Discovery vectors (up to ten)
1. Grep default-allow sentinels: `shouldPass = true`, `return true` in an `authorize`/`authenticate`, `AllowAll`, `AnonymousAuthenticator`.
2. Find anonymous mechanisms enabled by default and not explicitly disallowed.
3. Read authorizer bodies that ignore the authentication result and always permit.
4. Distinguish the admin plane from the data plane (a separate session type, SUPER/GRANT, admin command channel).
5. Mine tests named for anonymous/default access; they are ready-made PoCs (see test-oracle-mining).
6. Trace config keys that toggle auth and check the shipped default value, not the documented one.
7. Follow empty-credential handling: an empty password or missing auth packet that skips the auth switch.
8. Check protocol handshakes for an auth-optional path (a client that never sends an authenticate frame).
9. Inspect plugin registration: an auth plugin present but not wired into the request path.
10. Compare per-listener config: an internal listener with auth off that is actually reachable.

## Cross-language and stack examples
- C/C++ brokers/DBs: an anonymous authenticator default-on; `authorize()` returning true; empty-password accounts skipping the handshake.
- Java (Kafka-like/JMS): a `PLAINTEXT` listener with no SASL; an `Authorizer` returning ALLOWED on error.
- Go (NATS/etcd-like): auth disabled by default; a token check that treats empty as valid.
- Python (brokers/agents): a control endpoint on the native port with no auth; a SASL callback that returns true on exception.
- Node (queue/IoT gateways): an MQTT/AMQP bridge accepting anonymous connect; a management port without a token.
- Ruby (Sidekiq/AMQP tooling): a control endpoint with no Rack auth on the native port.
- Databases (MySQL/Postgres/Mongo-family): default accounts with empty passwords, `trust` auth, or an open bind.

## How to validate
Speak the native protocol (not an HTTP admin shim). Connect with empty identity or
no auth frame and run a privileged action (admin help, CREATE USER, GRANT, queue
delete) with a benign marker. Oracle: the privileged success body. Negative
control: the same action with auth enforced must be denied. Measure time-to-
privileged-action with vs without credentials; they must be equal if fail-open.
Require signed target-bound proof.

## Counterexamples and limits
A documented "auth disabled" on a loopback-only bind with no reachable admin verbs
is LATENT. Enforced authentication, disallowed anonymous credential, and an
authorizer that honors the authentication result refute the claim.

Evidence bar: a match here is a lead, not a finding - confirm with a bounded oracle (an unauthenticated client completing a privileged broker/DB operation), a passing negative control (the same operation is refused when the authenticator is enforced), and signed target-bound proof on the shipped artifact.
