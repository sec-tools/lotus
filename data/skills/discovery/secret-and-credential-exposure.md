# Skill: Hardcoded Secrets and Credential Exposure

## Metadata
- **Category**: discovery
- **Language**: multi-language
- **Stacks**: secrets, credentials, config, git, ci
- **Signals**: .env, id_rsa, .pem, credentials, aws_access_key_id, private_key, .npmrc, .git-credentials, .aws, secret_key_base

## Doctrine
A committed API key, private key, database URL, or signing secret in source, config,
history, CI logs, or a container layer is a lead requiring scope and exposure evidence.
Use synthetic credentials in the local lab to demonstrate the captured code's
unauthorized disclosure or access behavior. The validity, rotation status, and impact
of any discovered external credential remain unknown; never test it against its service.

## Discovery vectors (up to ten)
1. Grep for high-entropy strings and known key prefixes (cloud keys, tokens, `BEGIN` private-key blocks).
2. Search config, `.env`, sample configs, and checked-in secret files.
3. Walk git history and deleted files - a rotated-out secret may still be valid.
4. Inspect CI/CD config, build logs, and pipeline variables echoed into output.
5. Peel container image layers and Dockerfiles for `ARG`/`ENV` secrets and copied key files.
6. Check client bundles, mobile apps, and minified JS for embedded API keys.
7. Look for signing secrets (JWT `secret_key_base`, HMAC keys) that enable token forgery.
8. Find default or shared credentials in seeds, fixtures, and docs used in production.
9. Check backups, logs, and error dumps for credentials in transit.
10. Record the intended service and privilege from source; external validity remains unknown and must not be tested.

## Cross-language and stack examples
- Any language: a cloud access key or a `BEGIN PRIVATE KEY` block committed to source or history.
- Node: a token in `.npmrc`, a bundled frontend key, or a `config.js` with a live secret.
- Python/Ruby/PHP: `settings.py`/`secrets.yml`/`.env` with a database URL or signing key.
- Java/Go: `application.properties`/`application.yml` or a struct default holding a token.
- Infra: Terraform state, Kubernetes Secrets committed as plaintext, or a Dockerfile `ENV` secret.
- Mobile/desktop: a hardcoded key in an APK/IPA or an Electron/asar bundle.
- Git/CI: a secret in commit history, a `.git-credentials` file, or a CI log echoing a masked variable.

## How to validate
Treat discovered secrets as sensitive and redact their values from model context,
logs, and reports. Never use discovered credentials or call their external services.
In the isolated local lab, use synthetic credentials to reproduce an unauthorized
disclosure or privilege crossing through the captured code. A guarded build or
invalid synthetic credential must prevent the same effect. External validity remains
unknown; require signed target-bound proof for any demonstrated local behavior.

## Counterexamples and limits
An already-rotated, example, or test-only secret with no production scope is LATENT.
A high-entropy string that is not a credential (a hash, a public key, an asset
fingerprint) is a false positive.

Evidence bar: a secret-looking string is a lead, not a finding - confirm with a bounded oracle (unauthorized disclosure or access reproduced with synthetic credentials in the local lab), a passing negative control, and signed target-bound proof on the shipped artifact. Never use discovered credentials; external validity remains unknown.
