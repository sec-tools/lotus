"""Bounded, same-origin Gitlink capture; no target checkout hooks or execution.

Child Git objects live only in owned temporary bare repositories. Their exact
tracked blobs enter the controller's flat index; parent HEAD is never changed.
"""
from __future__ import annotations
import asyncio
import configparser
from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import tempfile
import time
from urllib.parse import urlsplit, urlunsplit
from backend import proof_receipts
from backend.async_process import terminate_and_reap

_PROCESS_KEY = os.urandom(32)
_RECEIPT = 'lotus-submodules.json'
_PURPOSE = 'lotus-pinned-submodules-v1'
_OID = re.compile(r'(?:[0-9a-f]{40}|[0-9a-f]{64})')
_CODES = {'missing-declaration','unsafe-declaration','unsafe-url','fetch-unavailable','missing-commit',
          'capture-limit','unsafe-tree','capture-timeout','capture-failed','declaration-without-gitlink'}

class CaptureError(ValueError):
    def __init__(self, code):
        self.code = code if code in _CODES else 'capture-failed'
        super().__init__('Pinned submodule capture: '+self.code)

@dataclass(frozen=True)
class Limits:
    modules: int = 16
    depth: int = 2
    files: int = 12000
    bytes: int = 128 * 1024 * 1024
    file_bytes: int = 16 * 1024 * 1024
    metadata_bytes: int = 16 * 1024 * 1024
    seconds: float = 180
    command_seconds: float = 90


def _path(value):
    if (not isinstance(value, str) or not value or len(value.encode()) > 1024 or '\\' in value
            or any(ord(c) < 32 or ord(c) == 127 for c in value)):
        raise CaptureError('unsafe-tree')
    parts = PurePosixPath(value).parts
    if value.startswith('/') or any(p in {'..','.git',''} for p in parts) or '/'.join(parts) != value:
        raise CaptureError('unsafe-tree')
    return value


def _origin(url):
    if not isinstance(url,str) or len(url)>2048 or re.search(r'[\s\\%]',url):
        raise CaptureError('unsafe-url')
    p=urlsplit(url)
    try:port=p.port
    except ValueError:raise CaptureError('unsafe-url') from None
    if (p.scheme!='https' or not p.hostname or p.username or p.password or p.query or p.fragment
            or port not in {None,443} or not re.fullmatch(r'[A-Za-z0-9.-]+',p.hostname)
            or p.hostname.startswith('.') or '..' in p.hostname):
        raise CaptureError('unsafe-url')
    if not p.path.startswith('/') or not p.path.strip('/') or any(x in {'.','..'} for x in p.path.split('/')):
        raise CaptureError('unsafe-url')
    return p


def resolve_url(parent, child):
    base=_origin(parent)
    if not isinstance(child,str) or re.search(r'[\s\\%?#@]',child):raise CaptureError('unsafe-url')
    if child.startswith(('https://','http://')):
        result=_origin(child)
    elif child.startswith(('./','../')):
        # Git resolves relative submodule URLs against the repository URL as a
        # directory, not RFC's containing directory. Never climb above origin.
        parts=base.path.strip('/').split('/')
        for part in child.split('/'):
            if part=='.':continue
            if part=='..':
                if not parts:raise CaptureError('unsafe-url')
                parts.pop()
            elif not part or not re.fullmatch(r'[A-Za-z0-9._-]+',part):raise CaptureError('unsafe-url')
            else:parts.append(part)
        result=_origin(urlunsplit(('https',base.netloc,'/'+('/'.join(parts)),'','')))
    else:raise CaptureError('unsafe-url')
    if (result.hostname.lower(),result.port or 443)!=(base.hostname.lower(),base.port or 443):
        raise CaptureError('unsafe-url')
    return urlunsplit(('https',result.netloc,result.path,'',''))


def git_environment():
    return {'PATH':os.environ.get('PATH','/usr/bin:/bin'),'LANG':'C.UTF-8',
            'GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':os.devnull,'GIT_TERMINAL_PROMPT':'0',
            'GIT_ASKPASS':'','GIT_LFS_SKIP_SMUDGE':'1','GIT_OPTIONAL_LOCKS':'0'}


def git_argv(directory,*args):
    opts={'core.hooksPath':os.devnull,'core.fsmonitor':'false','core.autocrlf':'false',
          'core.attributesFile':os.devnull,'credential.helper':'','core.askpass':'',
          'protocol.allow':'never','protocol.https.allow':'always','protocol.file.allow':'never',
          'http.followRedirects':'false','http.sslVerify':'true','fetch.fsckObjects':'true',
          'fetch.recurseSubmodules':'false','submodule.recurse':'false',
          'gc.auto':'0','pack.windowMemory':'16m','pack.threads':'1'}
    return ['git','--literal-pathspecs','-C',str(directory),*[v for k,x in opts.items() for v in ('-c',k+'='+x)],*args]


async def command(argv,*,input=None,timeout=90,limit=1024*1024,disk_root=None,disk_limit=128*1024*1024):
    """Bound output, elapsed time and owned download storage; reap on cancel."""
    p=await asyncio.create_subprocess_exec(*argv,stdin=asyncio.subprocess.PIPE if input is not None else asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE,env=git_environment(),start_new_session=True)
    async def read(stream,cap):
        result=bytearray()
        while True:
            data=await stream.read(65536)
            if not data:return bytes(result)
            result.extend(data)
            if len(result)>cap:raise CaptureError('capture-limit')
    async def feed():
        if input is not None:
            p.stdin.write(input);await p.stdin.drain();p.stdin.close()
    async def watch():
        if disk_root is None:
            await p.wait()
            return
        waiter=asyncio.create_task(p.wait())
        try:
            while p.returncode is None:
                total=0;count=0
                for folder,dirs,files in os.walk(disk_root,followlinks=False):
                    for name in files:
                        path=Path(folder)/name;count+=1
                        try:total+=path.lstat().st_size
                        except FileNotFoundError:continue
                        if total>disk_limit or count>50000:raise CaptureError('capture-limit')
                await asyncio.wait({waiter},timeout=.1)
        finally:
            if not waiter.done():waiter.cancel()
            await asyncio.gather(waiter,return_exceptions=True)
    tasks=[asyncio.create_task(read(p.stdout,limit)),asyncio.create_task(read(p.stderr,65536)),
           asyncio.create_task(feed()),asyncio.create_task(watch())]
    try:
        results=await asyncio.wait_for(asyncio.gather(*tasks),timeout=timeout)
        await p.wait()
        if p.returncode:raise CaptureError('fetch-unavailable')
        return results[0]
    except asyncio.TimeoutError:raise CaptureError('capture-timeout') from None
    finally:
        for task in tasks:
            if not task.done():task.cancel()
        await asyncio.gather(*tasks,return_exceptions=True)
        await terminate_and_reap(p,process_group=True)


def _tree(raw,limits):
    if len(raw)>limits.metadata_bytes:raise CaptureError('capture-limit')
    entries=[]
    try:
        for row in raw.split(b'\0'):
            if not row:continue
            prefix,name=row.split(b'\t',1);mode,kind,oid=prefix.decode('ascii').split(' ')
            name=_path(name.decode('utf-8'))
            if mode not in {'100644','100755','120000','160000'} or not _OID.fullmatch(oid):raise CaptureError('unsafe-tree')
            if kind!=('commit' if mode=='160000' else 'blob'):raise CaptureError('unsafe-tree')
            entries.append((mode,oid,name))
    except (UnicodeError,ValueError) as error:
        if isinstance(error,CaptureError):raise
        raise CaptureError('unsafe-tree') from None
    if len(entries)>100000 or len({x[2] for x in entries})!=len(entries):raise CaptureError('capture-limit')
    return entries


def _declarations(raw):
    if len(raw)>65536:raise CaptureError('unsafe-declaration')
    parser=configparser.ConfigParser(interpolation=None,strict=True,delimiters=('=',),comment_prefixes=('#',';'))
    try:parser.read_string(raw.decode('utf-8'))
    except (UnicodeError,configparser.Error):raise CaptureError('unsafe-declaration') from None
    result={}
    if parser.defaults():raise CaptureError('unsafe-declaration')
    for section in parser.sections():
        if not re.fullmatch(r'submodule "[^"\r\n]+"',section):raise CaptureError('unsafe-declaration')
        row=dict(parser[section])
        if set(row)-{'path','url','branch','ignore','shallow'} or not {'path','url'}<=set(row):raise CaptureError('unsafe-declaration')
        path=_path(row['path'].strip('"'));url=row['url'].strip('"')
        if path in result:raise CaptureError('unsafe-declaration')
        result[path]=url
    return result


def _index_names(root):
    import subprocess
    result=subprocess.run(git_argv(root,'ls-files','--stage','-z'),env=git_environment(),
                          stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=15)
    if result.returncode or len(result.stdout)>32*1024*1024:
        raise ValueError('Submodule receipt lacks bounded checkout tracking')
    return hashlib.sha256(result.stdout).hexdigest()


def _head(root):
    import subprocess
    p=subprocess.run(git_argv(root,'rev-parse','--verify','HEAD'),env=git_environment(),capture_output=True,timeout=10)
    value=p.stdout.decode('ascii',errors='replace').strip()
    if p.returncode:return ''
    if not _OID.fullmatch(value):raise ValueError('Submodule parent revision is invalid')
    return value


def validate_metadata(document):
    if not isinstance(document,dict) or len(json.dumps(document).encode())>24576:raise ValueError('Submodule metadata is malformed or oversized')
    if set(document)!={'schema_version','status','parent_revision','parent_url','modules','gaps'} or document['schema_version']!=1 or document['status'] not in {'complete','partial'}:raise ValueError('Submodule metadata is malformed')
    if not isinstance(document['parent_revision'],str) or not _OID.fullmatch(document['parent_revision']):raise ValueError('Submodule parent revision is invalid')
    if document['parent_url'] is not None:_origin(document['parent_url'])
    elif document['status']!='partial':raise ValueError('Missing submodule origin requires partial capture')
    modules,gaps=document['modules'],document['gaps']
    if not isinstance(modules,list) or len(modules)>16 or not isinstance(gaps,list) or len(gaps)>32:raise ValueError('Submodule metadata exceeds limits')
    if (document['status']=='complete')!=(not bool(gaps)):raise ValueError('Submodule completeness differs from gaps')
    paths=[]
    for row in modules:
        if not isinstance(row,dict) or set(row)!={'path','url','commit','files','bytes','depth','status'}:raise ValueError('Submodule metadata row is invalid')
        paths.append(_path(row['path']));resolve_url(document['parent_url'],row['url'])
        if not _OID.fullmatch(str(row['commit'])) or row['status'] not in {'captured','partial'}:raise ValueError('Submodule pin/status is invalid')
        if any(type(row[k]) is not int or row[k]<0 for k in ['files','bytes','depth']):raise ValueError('Submodule counts are invalid')
    if len(paths)!=len(set(paths)):raise ValueError('Submodule paths repeat')
    for row in gaps:
        if not isinstance(row,dict) or set(row)!={'path','url','commit','code'} or row['code'] not in _CODES:raise ValueError('Submodule gap is invalid')
        if row['path']:_path(row['path'])
        if row['url'] is not None:resolve_url(document['parent_url'],row['url'])
        if row['commit'] is not None and not _OID.fullmatch(str(row['commit'])):raise ValueError('Submodule gap pin is invalid')
    return deepcopy(document)


def _document(parent,url,modules,gaps):
    document={'schema_version':1,'status':'partial' if gaps else 'complete','parent_revision':parent,
              'parent_url':url,'modules':deepcopy(modules),'gaps':deepcopy(gaps)}
    if len(json.dumps(document).encode())>24576:
        document['status']='partial'
        document['gaps']=[{'path':'','url':None,'commit':None,'code':'capture-limit'}]
        while len(json.dumps(document).encode())>24576:document['modules'].pop()
    return document


def preserve_metadata(destination,document):
    document=validate_metadata(document);root=Path(destination).resolve();git=root/'.git'
    if git.is_symlink() or not git.is_dir():raise ValueError('Submodule metadata requires owned Git directory')
    body={'schema_version':1,'document':document,'index_sha256':_index_names(root),'head':_head(root)}
    raw=json.dumps(body,sort_keys=True,separators=(',',':')).encode();key=proof_receipts._signing_key() or _PROCESS_KEY
    body['signature']=proof_receipts.sign_blob(raw,purpose=_PURPOSE,key=key)
    path=git/_RECEIPT
    if path.exists() or path.is_symlink():raise ValueError('Submodule metadata already exists')
    with path.open('x') as f:json.dump(body,f,sort_keys=True)
    path.chmod(0o600)


def capture_metadata(source):
    root=Path(source).resolve();path=root/'.git'/_RECEIPT
    if not path.exists() and not path.is_symlink():return {}
    if (root/'.git').is_symlink() or path.is_symlink() or path.stat().st_size>32768:raise ValueError('Submodule metadata is unsafe')
    body=json.loads(path.read_text());signature=body.pop('signature','');raw=json.dumps(body,sort_keys=True,separators=(',',':')).encode()
    if not proof_receipts.verify_blob(raw,signature,purpose=_PURPOSE,key=proof_receipts._signing_key() or _PROCESS_KEY):raise ValueError('Submodule metadata authentication failed')
    if body.get('head')!=_head(root) or body.get('index_sha256')!=_index_names(root):raise ValueError('Submodule checkout identity changed')
    return validate_metadata(body['document'])


async def capture_checkout(root,parent_url,*,run=command,limits=Limits()):
    root=Path(root).resolve();started=time.monotonic();modules=[];gaps=[];selected=[];used_bytes=0;seen=0;finalizing=False
    async def git(directory,*args,input=None,limit=None,disk_root=None):
        remaining=limits.seconds+(30 if finalizing else 0)-(time.monotonic()-started)
        if remaining<=0:raise CaptureError('capture-timeout')
        return await run(git_argv(directory,*args),input=input,timeout=min(limits.command_seconds,remaining),
                         limit=limit or limits.metadata_bytes,disk_root=disk_root,disk_limit=limits.bytes)
    parent=(await git(root,'rev-parse','HEAD')).decode().strip()
    if not _OID.fullmatch(parent):raise CaptureError('missing-commit')
    try:entries=_tree(await git(root,'ls-tree','-rz','--full-tree',parent),limits)
    except CaptureError as error:
        document={'schema_version':1,'status':'partial','parent_revision':parent,'parent_url':None,'modules':[],
                  'gaps':[{'path':'','url':None,'commit':None,'code':error.code}]}
        preserve_metadata(root,document);return document
    top_links=[x for x in entries if x[0]=='160000']
    parent_files=sum(row[0]!='160000' for row in entries)
    if not top_links:return {}
    try:_origin(parent_url)
    except CaptureError:
        document={'schema_version':1,'status':'partial','parent_revision':parent,'parent_url':None,'modules':[],
                  'gaps':[{'path':name,'url':None,'commit':commit,'code':'unsafe-url'} for _,commit,name in top_links[:32]]}
        preserve_metadata(root,document);return document
    def gap(path,commit,code,url=None):
        if len(gaps)<32:gaps.append({'path':path,'url':url,'commit':commit,'code':code})
    async def declarations(directory,tree):
        candidate=next((x for x in tree if x[2]=='.gitmodules' and x[0]=='100644'),None)
        if not candidate:return {}
        return _declarations(await git(directory,'cat-file','blob',candidate[1],limit=65536))
    async def descend(directory,tree,url,prefix,stage,depth):
        nonlocal used_bytes,seen
        links=[x for x in tree if x[0]=='160000']
        if not links:return
        try:declared=await declarations(directory,tree)
        except CaptureError as error:
            for _,commit,name in links:gap(prefix+name,commit,error.code)
            return
        for extra in set(declared)-{x[2] for x in links}:gap(prefix+extra,None,'declaration-without-gitlink')
        for _,commit,name in links:
            path=prefix+name;child_url=None;seen+=1
            old_selected,old_modules,old_bytes=len(selected),len(modules),used_bytes
            try:
                if seen>limits.modules or depth>limits.depth:raise CaptureError('capture-limit')
                if name not in declared:raise CaptureError('missing-declaration')
                child_url=resolve_url(url,declared[name])
                with tempfile.TemporaryDirectory(prefix='lotus-submodule-') as temp:
                    bare=Path(temp)/'objects';bare.mkdir();empty=Path(temp)/'empty';empty.mkdir()
                    await git(bare,'init','--bare','--quiet','--object-format='+('sha256' if len(commit)==64 else 'sha1'),'--template='+str(empty))
                    await git(bare,'fetch','--quiet','--depth=1','--no-tags','--no-recurse-submodules','--',child_url,commit,disk_root=bare)
                    actual=(await git(bare,'rev-parse','FETCH_HEAD')).decode().strip()
                    if actual!=commit:raise CaptureError('missing-commit')
                    children=_tree(await git(bare,'ls-tree','-rz','--full-tree',commit),limits)
                    files=[x for x in children if x[0]!='160000']
                    if len(selected)+len(files)>limits.files or parent_files+len(selected)+len(files)>100000:raise CaptureError('capture-limit')
                    materialized=Path(temp).resolve()/'source';materialized.mkdir();own=[];size=0;links_to_create=[]
                    for mode,oid,relative in files:
                        data=await git(bare,'cat-file','blob',oid,limit=limits.file_bytes)
                        size+=len(data)
                        if used_bytes+size>limits.bytes:raise CaptureError('capture-limit')
                        target=materialized/relative;target.parent.mkdir(parents=True,exist_ok=True)
                        if mode=='120000':
                            try:link=data.decode('utf-8')
                            except UnicodeError:raise CaptureError('unsafe-tree') from None
                            try:contained=not Path(link).is_absolute() and (target.parent/link).resolve().is_relative_to(materialized)
                            except (OSError,RuntimeError):raise CaptureError('unsafe-tree') from None
                            if not contained:raise CaptureError('unsafe-tree')
                            links_to_create.append((target,link))
                        else:target.write_bytes(data);target.chmod(0o755 if mode=='100755' else 0o644)
                        own.append(path+'/'+relative)
                    for target,link in links_to_create:target.symlink_to(link)
                    try:valid_links=all(target.resolve().exists() for target,_ in links_to_create)
                    except (OSError,RuntimeError):raise CaptureError('unsafe-tree') from None
                    if not valid_links:raise CaptureError('unsafe-tree')
                    used_bytes+=size;selected.extend(own);before=len(gaps)
                    await descend(bare,children,child_url,path+'/',materialized,depth+1)
                    destination=stage/name
                    for ancestor in (destination,*destination.parents):
                        if ancestor==stage.parent:break
                        if ancestor.is_symlink():raise CaptureError('unsafe-tree')
                    if destination.exists() and (not destination.is_dir() or any(destination.iterdir())):raise CaptureError('unsafe-tree')
                    destination.parent.mkdir(parents=True,exist_ok=True)
                    shutil.copytree(materialized,destination,dirs_exist_ok=True,symlinks=True)
                    modules.append({'path':path,'url':child_url,'commit':commit,'files':len(files),'bytes':size,'depth':depth,
                                    'status':'partial' if len(gaps)>before else 'captured'})
            except CaptureError as error:
                del selected[old_selected:];del modules[old_modules:];used_bytes=old_bytes;gap(path,commit,error.code,child_url)
            except (OSError,UnicodeError,ValueError):
                del selected[old_selected:];del modules[old_modules:];used_bytes=old_bytes;gap(path,commit,'capture-failed',child_url)
    await descend(root,entries,parent_url,'',root,1)
    finalizing=True
    # Flatten only successfully materialized tracked files; HEAD and root Git
    # history remain the parent revision. Global config/filters/hooks are absent.
    try:
        for _,_,name in top_links:await git(root,'update-index','--force-remove','--',name)
        present=[name for name in selected if (root/name).is_file() or (root/name).is_symlink()]
        if present:await git(root,'add','--force','--pathspec-from-file=-','--pathspec-file-nul',input=b'\0'.join(n.encode() for n in present)+b'\0')
    except CaptureError as error:
        # The available flat index remains the selection authority. A failed
        # finalization can never advertise complete child capture.
        gap('',None,error.code)
        for row in modules:row['status']='partial'
    if _head(root)!=parent:raise CaptureError('missing-commit')
    document=_document(parent,parent_url,modules,gaps)
    preserve_metadata(root,document)
    return document


async def uncaptured_metadata(source, *, run=command):
    """Local Git inputs are read only; unavailable children stay explicit gaps."""
    source=Path(source).resolve()
    index=await run(git_argv(source,'ls-files','--stage','-z'),timeout=15,limit=32*1024*1024)
    if not any(row.startswith(b'160000 ') for row in index.split(b'\0')):return {}
    raw=await run(git_argv(source,'rev-parse','HEAD'),timeout=10,limit=256)
    head=raw.decode().strip()
    if not _OID.fullmatch(head):raise CaptureError('missing-commit')
    entries=_tree(await run(git_argv(source,'ls-tree','-rz','--full-tree',head),timeout=15,limit=16*1024*1024),Limits())
    links=[row for row in entries if row[0]=='160000']
    if not links:return {}
    return {'schema_version':1,'status':'partial','parent_revision':head,'parent_url':None,'modules':[],
            'gaps':[{'path':name,'url':None,'commit':commit,'code':'missing-declaration'} for _,commit,name in links[:32]]}
