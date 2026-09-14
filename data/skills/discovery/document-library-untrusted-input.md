# Skill: Untrusted Document and Parser Libraries

## Metadata
- **Category**: discovery
- **Language**: ruby python java c/cpp multi-format
- **Stacks**: pdf, office, xml, image, parser
- **Signals**: pyyaml, pypdf, pdf-reader, prawn, nokogiri, pdfbox, poi, pillow, lxml, jackson-dataformat-xml

## Doctrine
Document and media parsers ingest fully attacker-controlled bytes. The crown jewels
are code-execution and file primitives (deserialize, dynamic dispatch, file open/
write, external entity), not hang/recursion DoS. Prefer CVSS >= 7 leads.

## Discovery vectors (up to ten)
1. Find deserializers invoked on parser state: `Marshal.load`, `YAML.load`/`unsafe_load`, `pickle.loads`, `ObjectInputStream`.
2. Find dynamic dispatch of a name taken from the document (`send`, `getattr`, reflection) and check the allowlist.
3. Trace file operations whose path comes from a filespec, launch action, or embedded-file entry.
4. Look for external-entity and remote-reference features (XXE, `!include`, remote images, URLs) reaching a fetcher (SSRF).
5. Check whether encryption/permission bits are honored while decrypting (document-level authz).
6. Inspect embedded scripting (PDF JavaScript, Office macros, SVG scripts) and whether it executes.
7. Follow font/codec/decompression paths in native parsers for memory-corruption primitives.
8. Enumerate every format branch; the unsafe path is often a rarely used feature.
9. Mine the library's own tests and fuzz corpus for inputs that reach the dangerous branch.
10. Check version and known CVEs of the parser and whether the app calls the still-unsafe API.

## Cross-language and stack examples
- Ruby: `PDF::Reader` clone_state via `Marshal.load`; `Psych`/`YAML.load`; `Nokogiri` with entity loading; `send` on an operator name.
- Python: `PyYAML` full load, `Pillow`/image decoders, `lxml` with external-entity resolution enabled, or `pickle` in a loader. Trace the actual configured parser; an `xml.etree` import or a DOCTYPE alone does not demonstrate external file/network access.
- Java: XXE in `DocumentBuilder`/`SAXParser`/XSLT, Apache POI/PDFBox on untrusted docs, `ObjectInputStream` gadget chains.
- C/C++: font/image/codec parsers (memory safety), libxml2 entity expansion, archive members reaching path writes.
- Node: `libxmljs` when external-entity resolution is enabled, native `sharp` codecs, or a version-specific `pdf-parse`/`xlsx` parser issue. A package name such as `xml2js` alone is not evidence that external entities are resolved.
- PHP: `simplexml_load_string`/`DOMDocument` entity loading, `imagick`/GD decoders, `unserialize` of embedded metadata.
- Go: image decoders, custom resolvers that fetch document references, and parsed fields flowing into `text/template`. Do not infer external-resource resolution from `encoding/xml` alone; identify the actual resolver and its settings.

## How to validate
Feed one crafted document in an authorized lab. Oracles: `uid=` from a gadget or
embedded script; a sentinel file appearing under a lab-only write path; an
outbound request to a lab-controlled host for XXE/SSRF. Negative control: a safe
loader or disabled feature must reject the same payload. DISPROVE is mandatory
where an allowlist gates dispatch. Require signed target-bound proof.

## Counterexamples and limits
Safe-loaders, an enforced operator allowlist, disabled external entities, and
`extractall(filter='data')`-style hardening refute the RCE/file claims. A pure
hang or decompression bomb is DoS; cap it low and do not let it block P0/P1 work.
