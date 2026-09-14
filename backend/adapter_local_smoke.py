"""Fixed local protocol observations, separate from remote Deployments requests."""
from pathlib import Path
import hashlib
from backend.adapter_source_context import _context_paths, _excerpt, _safe_name

PROBE = 'aria2-version'
# These are source declarations supporting this one fixed read-only protocol.
# Detection aids planning; only the real response establishes runtime readiness.
_REQUIRED = {
    'src/json.cc': ('decodeGetParams(', '"method="', '"id="'),
    'src/HttpServer.cc': ('HttpServer::setupResponseRecv()', 'getMethod() == "GET"', 'path == "/jsonrpc"', 'RPC_TYPE_JSONP'),
    'src/HttpServerBodyCommand.cc': ('sendJsonRpcResponse(', 'res.code == 0', 'json::decodeGetParams(query)'),
    'src/RpcMethodImpl.cc': ('GetVersionRpcMethod::process(', 'result->put(KEY_VERSION, PACKAGE_VERSION)', 'result->put(KEY_ENABLED_FEATURES,', '"enabledFeatures"'),
}
MAX_FILE_BYTES = 1024 * 1024
MAX_INSPECTED_BYTES = 4 * MAX_FILE_BYTES


def _windows(text, markers):
    rows=[];remaining=4000
    for marker in markers:
        offset=text.find(marker)
        start=max(0,text.rfind('\n',0,max(0,offset-160))+1)
        end=min(len(text),offset+650)
        if any(start>=r['_start'] and end<=r['_end'] for r in rows):continue
        piece=text[start:end];encoded=piece.encode()[:remaining];piece=encoded.decode('utf-8',errors='ignore')
        if not piece:break
        rows.append({'_start':start,'_end':end,'start_line':text.count('\n',0,start)+1,
                     'text':piece,'scope':'Bounded source window; omitted regions are not displayed'})
        remaining-=len(piece.encode())
    return [{k:v for k,v in r.items() if not k.startswith('_')} for r in rows]


def available_probes(source, files, *, inventory=None):
    root=Path(source).resolve();inventory=_context_paths(root, inventory)
    prefixes=sorted(name[:-len('src/json.cc')] for name in inventory if name.endswith('src/json.cc') and _safe_name(name))[:2]
    inspected=0
    for prefix in prefixes:
        names=[prefix+n for n in _REQUIRED]
        if not all(n in inventory and _safe_name(n) for n in names):continue
        support=[]
        for name,markers in zip(names,_REQUIRED.values()):
            p=inventory[name]
            if (p.is_symlink() or not p.is_file() or not p.resolve().is_relative_to(root)
                    or any(parent.is_symlink() for parent in p.parents if parent!=root)
                    or p.stat().st_size>MAX_FILE_BYTES):break
            if inspected+p.stat().st_size>MAX_INSPECTED_BYTES:break
            with p.open('rb') as handle:raw=handle.read(MAX_FILE_BYTES+1)
            inspected+=len(raw)
            if len(raw)>MAX_FILE_BYTES or inspected>MAX_INSPECTED_BYTES or b'\x00' in raw:break
            try:text=raw.decode('utf-8')
            except UnicodeError:break
            if not all(marker in text for marker in markers):break
            support.append((name,raw,_windows(text,markers)))
        if len(support)!=len(_REQUIRED):continue
        refs=[]
        for name,raw,windows in support:
            row=next((r for r in files if r['file']==name),None)
            digest=hashlib.sha256(raw).hexdigest()
            if row is not None and row['sha256']!=digest:return []
            if row is None:
                row={'file':name,**_excerpt(raw)};files.append(row)
            row['local_probe_windows']=windows
            refs.append({'file':name,'sha256':digest})
        return [{'probe':PROBE,'source_evidence':refs,'scope':'Source declaration support only; not runtime verification',
                 'request':'Fixed local GET /jsonrpc?method=aria2.getVersion&id=lotus-smoke, no parameters or credentials',
                 'success':'HTTP200, matching id, no error, result.version and result.enabledFeatures; no finding proof'}]
    return []


def validate_probe(smoke, context, cited):
    if not isinstance(smoke,dict) or set(smoke)!={'probe'} or smoke['probe']!=PROBE:
        raise ValueError('Unknown or modified fixed local protocol probe')
    files={r['file']:r['sha256'] for r in context.get('files',[])}
    for available in context.get('available_local_probes') or []:
        refs=available.get('source_evidence') or []
        if (available.get('probe')==PROBE and len(refs)==4
                and all(r.get('file') in cited and files.get(r['file'])==r.get('sha256') for r in refs)):
            return {'probe':PROBE}
    raise ValueError('Local version probe requires its supplied captured implementation citations')



def request_path(smoke):
    if smoke != {'probe': PROBE}:
        raise ValueError('Unknown or modified fixed local protocol probe')
    return '/jsonrpc?method=aria2.getVersion&id=lotus-smoke'


def version_result(status, body):
    import json
    if len(body)>65536 or status!=200:
        return False
    def unique_object(pairs):
        value={}
        for key,item in pairs:
            if key in value:raise ValueError('duplicate RPC field')
            value[key]=item
        return value
    try:
        value=json.loads(body,object_pairs_hook=unique_object)
    except (ValueError,UnicodeError):
        return False
    if (not isinstance(value,dict) or value.get('id')!='lotus-smoke' or 'error' in value
            or not isinstance(value.get('result'),dict)):
        return False
    result=value['result'];version=result.get('version');features=result.get('enabledFeatures')
    return (isinstance(version,str) and 1<=len(version)<=128 and version[0].isdigit()
            and not any(ord(c)<32 for c in version)
            and isinstance(features,list) and len(features)<=128
            and all(isinstance(x,str) and 1<=len(x)<=128 and not any(ord(c)<32 for c in x) for x in features))


def observation_script():
    # The exact same controller-authored predicate is used by the compatibility
    # in-Pod smoke entrypoint; no application code or module is imported there.
    import inspect
    prefix = 'import http.client,json,sys\n' + inspect.getsource(version_result)
    return prefix + """s=json.loads(sys.argv[1])
if set(s)!={'probe','port'} or s['probe']!='aria2-version' or type(s['port']) is not int or not 1024<=s['port']<=65535:
    raise RuntimeError('invalid fixed local observation')
c=http.client.HTTPConnection('127.0.0.1',s['port'],timeout=10)
c.request('GET','/jsonrpc?method=aria2.getVersion&id=lotus-smoke',headers={'Connection':'close','Accept-Encoding':'identity'})
r=c.getresponse()
b=r.read(65537)
c.close()
if not version_result(r.status,b):
    raise RuntimeError('local version RPC did not return a bounded matching success result')
print('Captured application read-only version assertion passed')
"""
