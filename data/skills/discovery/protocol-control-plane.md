# Skill: Native Protocol Control Plane

## Metadata
- **Category**: discovery
- **Language**: c/cpp go java multi-protocol
- **Stacks**: grpc, redis, memcached, amqp, kafka, mysql, postgres, mongodb, broker
- **Signals**: grpcio, redis, protobuf, thrift, resp

## Doctrine
Binary and text wire protocols hide their admin surface from HTTP-only probes. If
you probe a binary protocol with HTTP requests you will miss every bug and wrongly
conclude "no admin surface". Map the real framing and hand Phase 2 a trace.

## Method
1. Map every listen/bind, config `port`, and docker-compose published port.
2. Distinguish data plane from admin plane (a distinct session type, an admin command channel, a privileged verb).
3. Produce a trace JSON for Phase 2: ports, framing, handshake, and the oracle for each privileged action.
4. Never conclude "no admin surface" from HTTP probes against a binary protocol.

## Discovery vectors (up to ten)
1. Enumerate listeners from bind/listen calls, config, and compose/k8s service ports.
2. Identify the framing: length-prefix, magic bytes, protobuf, JSON-over-TCP, MySQL/Postgres greeting.
3. Separate admin verbs from data verbs in the command table or opcode enum.
4. Read the client SDK/tests to learn the exact handshake and admin call sequence.
5. Capture a real session with a packet dump to recover byte layout and auth steps.
6. Check for an auth-optional or admin-optional path in the handshake state machine.
7. Look for a debug/monitoring port (pprof, JMX, metrics, replication) exposed without auth.
8. Map replication/cluster protocols that trust peers and are reachable by attackers.
9. Note text protocols (Redis RESP, memcached) where commands are trivially forgeable.
10. Cross-reference the admin plane with fail-open-native-auth for default-allow behavior.

## Cross-language and stack examples
- BlazingMQ-style: a length prefix plus event header plus JSON; an admin client type distinct from data.
- MySQL/OceanBase-style: greeting then handshake; empty-password accounts skip the auth switch.
- gRPC: reflection enabled exposing methods; server interceptors as the only auth.
- AMQP/Kafka: management vs data listeners; RESP or memcached text commands with no auth.
- Redis: `CONFIG SET dir`/`SAVE`/module load as a control-plane-to-write/execute pivot.
- etcd/Consul/ZooKeeper: an unauthenticated client API or a peer port exposing cluster mutation.
- Custom TCP/UDP daemons: a binary opcode dispatcher where an admin opcode skips the auth check.

## How to validate
Build a minimal client that speaks the framing, complete the handshake (or skip it
if optional), and invoke one admin verb with a benign marker; the negative control
is the same verb under enforced auth. Record the exact bytes and the observed state
change; require signed target-bound proof.

## Counterexamples and limits
An admin plane bound to loopback only, or one that enforces auth on every verb, is
LATENT. A listening socket or successful handshake is not impact by itself.

Evidence bar: a match here is a lead, not a finding - confirm with a bounded oracle (an unauthenticated admin/control frame causing a privileged state change or disclosing protected data), a passing negative control (the same frame is rejected once auth is required), and signed target-bound proof on the shipped artifact.
