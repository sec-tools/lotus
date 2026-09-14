"""Bounded captured filename catalogue and a read-only primary request schema."""
from pathlib import Path, PurePosixPath
import json
import re
from backend.adapter_source_context import _context_paths, _safe_name, _is_manifest, _is_doc, _is_config, _is_docker

MAX_PATHS = 512
MAX_CATALOGUE_BYTES = 64 * 1024
MAX_REQUEST_FILES = 16
_TEMPLATES = {'.html','.htm','.hbs','.handlebars','.ejs','.pug','.jinja','.jinja2','.j2','.tmpl','.tpl','.erb'}
_TEXT_SOURCE = {'.java','.kt','.scala','.c','.cc','.cpp','.h','.hpp','.py','.go','.rs','.js','.mjs','.cjs','.ts','.rb','.php','.sh','.cmd','.bat','.xml','.yaml','.yml','.properties','.json','.toml','.ini','.cfg','.md','.rst','.txt'}
_RUNTIME = re.compile(r'standalone|bootstrap|launcher|startup|(?:^|[._/-])start(?:[._/-]|$)', re.I)
_ENTRY = re.compile(r'main|server|service|handler|endpoint|rpc|httpserver|config|application', re.I)


def catalogue(source, *, inventory=None):
    root=Path(source).resolve();groups=[[],[],[],[]]
    for name in _context_paths(root, inventory):
        if not _safe_name(name):continue
        part=PurePosixPath(name)
        if not (part.suffix.lower() in (_TEXT_SOURCE | _TEMPLATES) or _is_manifest(name) or _is_docker(name) or name=='.gitmodules'):continue
        if _RUNTIME.search(name):tier=0
        elif (_is_config(name) or _is_doc(name) or _ENTRY.search(part.name)
              or part.suffix.lower() in _TEMPLATES and part.stem.lower() in {'index','default','layout','base'}):tier=1
        elif _is_manifest(name) or _is_docker(name) or name=='.gitmodules':tier=2
        else:tier=3
        groups[tier].append(name)
    # Round-robin directory groups within each relevance tier. A single large
    # source/module directory cannot consume every remaining filename slot.
    ordered=[]
    for names in groups:
        dirs={}
        for name in sorted(names):dirs.setdefault(str(PurePosixPath(name).parent),[]).append(name)
        index=0
        while dirs:
            empty=[]
            for key in sorted(dirs):
                values=dirs[key]
                if index<len(values):ordered.append(values[index])
                else:empty.append(key)
            for key in empty:dirs.pop(key)
            index+=1
    selected=[];used=1024
    for name in ordered:
        size=len(json.dumps(name,ensure_ascii=True).encode())+1
        if len(selected)>=MAX_PATHS or used+size>MAX_CATALOGUE_BYTES:break
        selected.append(name);used+=size
    return {'schema_version':1,'paths':selected,'listed_files':len(selected),'eligible_files':len(ordered),
            'omitted_files':len(ordered)-len(selected),'scope':'Captured filenames only, not inspected content or runnable-component proof; catalogue is bounded and may be incomplete.'}


def parse_request(value, context):
    if not isinstance(value,dict) or value.get('request')!='read_source':return None
    if set(value)!={'request','files','reason'}:
        raise ValueError('Source read request requires only request, files and reason')
    refs=value['files'];reason=value['reason']
    if (not isinstance(refs,list) or not 1<=len(refs)<=MAX_REQUEST_FILES
            or any(not isinstance(ref,str) or not _safe_name(ref) for ref in refs)
            or len(set(refs))!=len(refs)):
        raise ValueError('Source read request requires 1..16 unique safe captured paths')
    if (not isinstance(reason,str) or not reason.strip() or len(reason)>500
            or any(ord(c)<32 for c in reason)):
        raise ValueError('Source read request requires a bounded one-line explanation')
    known=set((context.get('source_catalogue') or {}).get('paths') or [])
    if any(ref not in known for ref in refs):
        raise ValueError('Source read request names a file outside the supplied captured catalogue')
    return refs


def parse_response(text):
    # The legacy extractor tries arrays first, which can mistake a request's
    # sole files array for its outer object. Prefer the complete JSON document.
    try:
        return json.loads(text)
    except ValueError:
        fenced = re.fullmatch(r"\s*```(?:json)?\s*(.*?)\s*```\s*", text, re.S)
        if fenced:
            return json.loads(fenced[1])
        from backend.ai_gateway import extract_json
        return extract_json(text)
