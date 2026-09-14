# Skill: Native Plugin / Dynamic-Load RCE

## Metadata
- **Category**: discovery
- **Language**: c/cpp go python java multi-runtime
- **Stacks**: plugin, native, extension
- **Signals**: ctypes, cffi, jna, jni, dlopen, loadlibrary
- **Unique vs**: java-gateway-plugin-script-rce (Groovy/SpEL scripts) and plugin-script-engine-rce (embedded interpreters). This skill is loading a native/module artifact from disk.

## Doctrine
Loading code from a path is RCE if the path or its contents are attacker-influenced.
Trace every dynamic-load argument to its origin: compile-time constant, config
file, environment, or an admin/unauthenticated command. Config-only origin is
PRECONDITIONED unless an attacker can change that config.

## Discovery vectors (up to ten)
1. Grep dynamic-load sinks: `dlopen`/`LoadLibrary`, Go `plugin.Open`, Python `ctypes.CDLL`/`imp`/`importlib` of a path, Java `System.load`/`URLClassLoader`, Node `require(userVar)`.
2. Trace each load argument backward to constant, config, env, or request.
3. Check whether the loaded path or directory is attacker-writable (permissions, upload dir, tmp).
4. Look for search-path hijacks: `LD_LIBRARY_PATH`, `PATH`, `DYLD_*`, RPATH, current-directory load.
5. Find plugin registries/manifests where an entry names a module to load.
6. Check admin or unauthenticated endpoints that set the plugin path or trigger a reload.
7. Inspect auto-load of modules from a directory the app scans at startup or on demand.
8. Follow package/extension install flows that fetch and load code.
9. Check integrity: is the artifact signature/hash verified before load?
10. Note version pinning bypasses where a user controls which module version loads.

## Cross-language and stack examples
- C/C++: `dlopen(config_path)`; RPATH or `LD_LIBRARY_PATH` pointing at a writable dir.
- Go: `plugin.Open(userPath)`; a module path from an HTTP handler.
- Python: `ctypes.CDLL(name)`, `importlib.import_module(user)`, `__import__` of a request value.
- Java: `URLClassLoader` over an attacker URL; `System.load` of an uploaded `.so`.
- Node: `require(variable)` resolving into an attacker-writable path; a native addon load.
- Rust: `libloading::Library::new(user_path)` and a dynamically-resolved symbol.
- .NET: `Assembly.LoadFrom`/`LoadFile` of an attacker path; `Activator.CreateInstance`.

## How to validate
Only if the load path is attacker-writable or attacker-named: drop a sentinel
module that writes a lab-only marker (or prints `uid=`) and confirm it loads.
Negative control: with a constant, verified path the sentinel must not load.
Require signed target-bound proof.

## Counterexamples and limits
A compile-time-constant path, a signature/hash-verified artifact, or a load
directory writable only by root refutes the RCE claim (LATENT/PRECONDITIONED).

Evidence bar: a match here is a lead, not a finding - confirm with a bounded oracle (your planted library's constructor or a unique marker executing), a passing negative control (a path outside the trusted plugin directory is refused), and signed target-bound proof on the shipped artifact.
