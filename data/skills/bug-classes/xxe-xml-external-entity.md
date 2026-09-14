# Skill: XML External Entity and Unsafe XML Parsing (bug class)

## Metadata
- **Category**: bug-classes
- **Language**: multi-language
- **Stacks**: xml, soap, saml, svg, office-xml, xslt
- **Signals**: documentbuilder, saxparser, xmlreader, lxml, etree, libxml2, nokogiri, expat, xstream, resolve_entities, doctype
- **Unique vs**: document-library-untrusted-input (parser libraries fed untrusted documents). This is XML-entity handling in request-facing XML: APIs, SOAP, SAML, SVG, and office-XML uploads.

## Doctrine
Untrusted XML that causes external resource resolution is an XXE lead; accepting a
DOCTYPE alone is not proof. Demonstrate the claimed file read, forbidden fetch, or
resource-limit violation. SAML or SOAP signature bypass requires separate evidence. The bug is a parser configured to load external
entities; the fix is disabling DOCTYPE and external entities. Any XML endpoint is in
scope until proven safe.

## Discovery vectors (up to ten)
1. Grep XML parser construction and check whether DOCTYPE and external entities are disabled.
2. Find request-facing XML: SOAP endpoints, XML APIs, and XML-RPC handlers.
3. Find file uploads that are XML underneath: SVG, DOCX/XLSX/PPTX, SAML assertions, RSS/Atom.
4. Test an external-entity probe pointing at a lab-only file and an out-of-band URL (blind XXE).
5. Check for parameter entities and out-of-band exfiltration when direct reflection is absent.
6. Assess denial of service via entity expansion and nested entity limits.
7. Check XInclude and XSLT document loading or external stylesheets as entity-adjacent vectors.
8. In SAML or SOAP, check whether entity or comment handling enables a signature-wrapping bypass.
9. Trace whether resolved entity content is reflected (full read) or only observable out-of-band (blind).
10. Look for language defaults that are unsafe (older libxml2, some Java parsers) versus hardened configs.

## Cross-language and stack examples
- Java: `DocumentBuilderFactory`/`SAXParser`/`XMLReader` without disallow-doctype-decl; XStream or JAXB.
- Python: `lxml.etree` with `resolve_entities=True`, or `xml.etree`/`xml.sax` on untrusted input.
- PHP: entity loading left enabled on older runtimes; `simplexml_load_string` on user XML.
- Ruby/Go/dotnet: Nokogiri with entity loading enabled; XML readers with DTD processing on.
- Uploads: an SVG avatar or an office-XML document parsed server-side with entities enabled.
- Node: `libxmljs`/`node-expat` with entity expansion enabled; a SAML library parsing assertions.
- .NET: `XmlDocument`/`XmlReader` with `DtdProcessing=Parse` and an `XmlResolver` set.

## How to validate
In an authorized lab, submit an entity referencing a lab-only sentinel file or an
out-of-band URL and confirm retrieval; the oracle is the sentinel content reflected
or the out-of-band callback firing. Negative control: a parser with DOCTYPE and
entities disabled must not resolve it. Require signed target-bound proof.

## Counterexamples and limits
A parser with DOCTYPE and external entities disabled, or input that is not parsed as
XML, refutes XXE (LATENT). A DOCTYPE echoed in an error without entity resolution is a
lead only.

Evidence bar: a DOCTYPE reaching a parser is a lead, not a finding - confirm with a bounded oracle (a lab sentinel file read via an entity or an out-of-band callback), a passing negative control (a hardened parser refuses to resolve entities), and signed target-bound proof on the shipped artifact.
