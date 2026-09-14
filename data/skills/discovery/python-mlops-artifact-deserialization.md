# Skill: ML/Artifact Deserialization and Model Loading

## Metadata
- **Category**: discovery
- **Language**: python multi-runtime
- **Stacks**: mlflow, huggingface, pytorch, sklearn, joblib, ray, kubeflow, ml
- **Signals**: torch, cloudpickle, joblib, numpy, mlflow, transformers, scikit-learn

## Doctrine
ML artifact ingestion is a high-value trust boundary: model and pipeline files
routinely execute code on load. Trace uploads, registries, and object-store
references into deserializers, and distinguish trusted operator artifacts from
attacker-controlled or cross-tenant input.

## Discovery vectors (up to ten)
1. Grep artifact loaders: `pickle`/`cloudpickle`/`joblib.load`, `torch.load`, `numpy.load(allow_pickle=True)`, `yaml.load`, custom `__reduce__` paths.
2. Trace the artifact source: user upload, model registry, object store URL, cross-tenant bucket.
3. Check whether a loader executes code on deserialize (pickle-backed formats do).
4. Distinguish safe formats (safetensors, ONNX-as-data) from code-executing ones.
5. Inspect model-server endpoints that load a user-named artifact by path or URL.
6. Follow pipeline/config files (`conda`/`requirements`/entrypoints) that run on load.
7. Check registry/experiment tooling that auto-loads artifacts.
8. Look for tar/zip model bundles extracted without path checks (traversal-to-overwrite).
9. Verify signature/hash checks before load.
10. Assess multi-tenant isolation of artifact stores and caches.

## Cross-language and stack examples
- PyTorch: `torch.load(user_file)` (pickle-backed) running a `__reduce__` gadget on load; `weights_only=False`.
- scikit-learn/joblib: `joblib.load`/`pickle.load` of an uploaded `.pkl`/`.joblib` model.
- TensorFlow/Keras: custom objects or `Lambda` layers only where the exact loader version, artifact format, and configuration permit executable deserialization. HDF5 or SavedModel filenames alone do not establish code execution.
- NumPy: `numpy.load(..., allow_pickle=True)` on an untrusted `.npy`/`.npz`.
- MLflow/Hugging Face registries: loading a request-referenced artifact into a pickle-backed loader.
- cloudpickle/dill/PyYAML: `cloudpickle.load`, `dill.load`, `yaml.load` of a params or config file.
- Negative-control candidates: a data-only format or a restricted `weights_only=True` loader must reject the same unsafe artifact under the captured loader version and configuration. Format names and flags alone do not establish safety; check custom operators, allowlisted objects, extraction, and downstream code paths.

## How to validate
In an authorized, isolated lab, load a benign artifact whose `__reduce__` writes a
lab-only marker (or prints `uid=`) and confirm execution. The negative control must
reject that same unsafe artifact under an enforced trust or loader restriction,
while a valid authorized artifact still loads. Merely loading a different harmless
file is not a negative control. Require signed target-bound proof.

## Counterexamples and limits
An RCE claim is refuted only for the observed path when the captured loader rejects
the unsafe artifact or enforced provenance excludes attacker-controlled artifacts.
A hash alone establishes identity, not authorization; assess who supplies it.
An extraction filter is relevant only to the traversal behavior it actually blocks.
Other parser, custom-operator, and downstream execution paths remain separate leads.

Evidence bar: a match here is a lead, not a finding - confirm with a bounded oracle (a pickle-backed load executing a gadget marker), a passing negative control (a safetensors or allowlisted load rejects the same artifact), and signed target-bound proof on the shipped artifact.
