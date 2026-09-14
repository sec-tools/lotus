"""Captured Node/pnpm and Go declarations become verified per-image toolchains.

Only metadata is read by the controller. Archives and executables are handled
inside the admitted image builder; the common base remains unchanged.
"""
import asyncio
import base64
import hashlib
import json
from pathlib import Path
import re

import httpx

VERSION = r'(?:0|[1-9][0-9]{0,3})\.(?:0|[1-9][0-9]{0,3})\.(?:0|[1-9][0-9]{0,3})'


class ToolchainUnavailable(ValueError):
    pass


def _version(value):
    if not isinstance(value, str) or not re.fullmatch('v?'+VERSION, value.strip()):
        raise ToolchainUnavailable('Source toolchain requires an exact supported version; ranges and moving aliases cannot select an archive')
    return value.strip().removeprefix('v')


def requirements(source):
    root=Path(source).resolve();refs=[]
    def read(name):
        path=root/name
        if not path.exists():return None
        if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(root) or path.stat().st_size>65536:
            raise ToolchainUnavailable('Source toolchain declaration is not a bounded regular captured file')
        raw=path.read_bytes()
        if len(raw)>65536:raise ToolchainUnavailable('Source toolchain declaration exceeds the read limit')
        refs.append({'file':name,'sha256':hashlib.sha256(raw).hexdigest()})
        try:return raw.decode('utf-8')
        except UnicodeError:raise ToolchainUnavailable('Source toolchain declaration is not valid UTF-8 text') from None
    go=_go_requirements(read)
    pins=[]
    for name in ('.nvmrc','.node-version'):
        text=read(name)
        if text is not None:pins.append(_version(text))
    raw=read('package.json');package={}
    if raw is not None:
        try:package=json.loads(raw)
        except (ValueError,RecursionError):raise ToolchainUnavailable('Captured package.json is not valid bounded JSON') from None
        if not isinstance(package,dict):raise ToolchainUnavailable('Captured package.json must be an object')
    dev=package.get('devEngines',{})
    runtime=dev.get('runtime',{}) if isinstance(dev,dict) else {}
    if isinstance(runtime,dict) and runtime.get('name')=='node':pins.append(_version(runtime.get('version')))
    manager=package.get('packageManager')
    if not pins:
        if manager is not None:raise ToolchainUnavailable('Exact package manager declared without a supported exact Node version; capture a compatible Node pin')
        return {'schema_version':1,'node':None,'pnpm':None,'go':go,'source_evidence':refs} if go else None
    if len(set(pins))!=1:raise ToolchainUnavailable('Captured Node version declarations conflict; no toolchain was selected')
    node=pins[0]
    engines=package.get('engines',{})
    if isinstance(engines,dict) and engines.get('node') and not _satisfies(node,engines['node']):
        raise ToolchainUnavailable('Captured exact Node version does not satisfy the declared engine requirement')
    value={'schema_version':1,'node':node,'source_evidence':refs,'pnpm':None}
    if go:value['go']=go
    if manager is not None:
        match=re.fullmatch(r'pnpm@('+VERSION+r')(?:\+sha512\.([a-fA-F0-9]{128}))?',str(manager))
        if not match:raise ToolchainUnavailable('Declared package manager is outside the exact Node/pnpm provisioning contract')
        value['pnpm']={'version':match[1],'source_sha512':match[2].lower() if match[2] else None}
    return value


def _go_requirements(read):
    """Resolve release names from bounded root module/workspace declarations.

    A language-only Go 1.21+ minimum maps to its initial .0 release, not a
    moving latest version. An explicit suggested toolchain must meet every
    captured minimum; conflicting suggestions are not silently discarded.
    """
    minima=[];suggestions=[];legacy_minima=set();explicit_minima=set()
    for name in ('go.mod','go.work'):
        raw=read(name)
        if raw is None:continue
        directives={}
        for line in raw.splitlines():
            line=line.split('//',1)[0].strip()
            match=re.match(r'^(go|toolchain)(?:\s|$)',line)
            if not match:continue
            fields=line.split();kind=match[1]
            if len(fields)!=2 or kind in directives:
                raise ToolchainUnavailable('Captured Go version directives are malformed or duplicated')
            directives[kind]=fields[1]
        if 'go' in directives:
            value=directives['go']
            if re.fullmatch(r'1\.(?:0|[1-9][0-9]{0,3})',value):
                if int(value.split('.')[1])<21:legacy_minima.add(value+'.0')
                value+='.0'
            else:explicit_minima.add(value)
            if not re.fullmatch(VERSION,value) or not value.startswith('1.'):
                raise ToolchainUnavailable('Captured Go minimum must be a supported release version')
            minima.append(_version(value))
        if 'toolchain' in directives and directives['toolchain']!='default':
            value=directives['toolchain']
            if not re.fullmatch('go'+VERSION,value):
                raise ToolchainUnavailable('Captured Go toolchain must name an exact official release')
            value=_version(value[2:])
            if not value.startswith('1.'):
                raise ToolchainUnavailable('Captured Go toolchain must name an exact official release')
            suggestions.append(value)
    if not minima and not suggestions:return None
    if len(set(suggestions))>1:
        raise ToolchainUnavailable('Captured Go toolchain declarations conflict')
    order=lambda value:tuple(map(int,value.split('.')))
    minimum=max(minima,key=order) if minima else suggestions[0]
    # Preserve older minimum-only modules on the pinned base. Before Go1.21
    # the initial release is named go1.N, not the nonexistent go1.N.0.
    if not suggestions and minimum in legacy_minima and minimum not in explicit_minima:return None
    selected=suggestions[0] if suggestions else minimum
    if order(selected)<order(minimum):
        raise ToolchainUnavailable('Captured Go toolchain is older than the module/workspace minimum')
    return {'version':selected,'minimum':minimum,'selection':'captured-toolchain' if suggestions else 'captured-go-minimum',
            'distribution':'official-go-toolchain-module','checksum_database':'sum.golang.org'}


def _satisfies(version, expression):
    """Conservative common Node engine syntax; unsupported syntax blocks."""
    if not isinstance(expression,str) or len(expression)>200:raise ToolchainUnavailable('Unsupported Node engine requirement')
    actual=tuple(map(int,version.split('.')))
    alternatives=expression.split('||')
    outcomes=[]
    for alternative in alternatives:
        tokens=alternative.strip().split();matches=[]
        if not tokens:raise ToolchainUnavailable('Unsupported Node engine requirement')
        for token in tokens:
            match=re.fullmatch(r'(\^|~|>=|<=|>|<|=)?('+VERSION+r')',token)
            if not match:raise ToolchainUnavailable('Unsupported Node engine requirement; supply a compatible exact captured pin')
            operator=match[1] or '=';wanted=tuple(map(int,match[2].split('.')))
            if operator=='^':
                major,minor,patch=wanted;upper=(major+1,0,0) if major else ((0,minor+1,0) if minor else (0,0,patch+1));good=wanted<=actual<upper
            elif operator=='~':good=wanted<=actual<(wanted[0],wanted[1]+1,0)
            else:good={'=':actual==wanted,'>':actual>wanted,'<':actual<wanted,'>=':actual>=wanted,'<=':actual<=wanted}[operator]
            matches.append(good)
        outcomes.append(all(matches))
    return any(outcomes)


async def resolve(spec):
    if spec is None:return None
    node=_version(spec['node']) if spec.get('node') else None
    async def fetch(url):
        async with httpx.AsyncClient(trust_env=False,follow_redirects=False,timeout=httpx.Timeout(10,connect=5)) as client:
            async with client.stream('GET',url,headers={'Accept':'application/json,text/plain','Accept-Encoding':'identity'}) as response:
                if response.status_code!=200:raise ToolchainUnavailable('Official source-pinned toolchain metadata was unavailable')
                chunks=[];count=0
                async for chunk in response.aiter_bytes():
                    count+=len(chunk)
                    if count>131072:raise ToolchainUnavailable('Official toolchain metadata exceeded its bounded read limit')
                    chunks.append(chunk)
                return b''.join(chunks)
    async def get(url):
        return await asyncio.wait_for(fetch(url),timeout=15)
    try:
        result={**spec,'installation_scope':'Prepared before repository build steps; versions are requirements, not runtime proof'}
        if spec.get('go'):
            version=_version(spec['go']['version']);identities={}
            for arch in ('arm64','amd64'):
                identity='v0.0.1-go'+version+'.linux-'+arch
                raw=await get('https://proxy.golang.org/golang.org/toolchain/@v/'+identity+'.info')
                if json.loads(raw).get('Version')!=identity:
                    raise ToolchainUnavailable('Official Go toolchain metadata did not match the selected release and platform')
                identities[arch]=hashlib.sha256(raw).hexdigest()
            result['go']={**spec['go'],'version':version,'metadata_sha256':identities}
        if node is None:return result
        sums=await get(f'https://nodejs.org/dist/v{node}/SHASUMS256.txt')
        lines=sums.decode('ascii').splitlines();archives={}
        for architecture in ('arm64','x64'):
            name=f'node-v{node}-linux-{architecture}.tar.xz'
            values=[line.split()[0] for line in lines if len(line.split())==2 and line.split()[1]==name]
            if len(values)!=1 or not re.fullmatch('[a-f0-9]{64}',values[0]):raise ToolchainUnavailable('Official Node checksum for a supported build architecture is absent or ambiguous')
            archives[architecture]={'url':f'https://nodejs.org/dist/v{node}/{name}','sha256':values[0]}
        result={**result,'node':node,'archives':archives,'metadata_sha256':hashlib.sha256(sums).hexdigest(),
                'architecture_selection':'Linux arm64/x64 chosen in the admitted builder; archive checksum verified before extraction',
                'installation_scope':'Prepared before repository build steps; versions are requirements, not runtime proof'}
        if spec.get('pnpm'):
            version=_version(spec['pnpm']['version']);raw=await get('https://registry.npmjs.org/pnpm/'+version)
            data=json.loads(raw);dist=data.get('dist',{});expected='https://registry.npmjs.org/pnpm/-/pnpm-'+version+'.tgz'
            if data.get('version')!=version or dist.get('tarball')!=expected:raise ToolchainUnavailable('Official package-manager identity did not match the captured exact version')
            integrity=dist.get('integrity','')
            if not isinstance(integrity,str) or not integrity.startswith('sha512-'):raise ToolchainUnavailable('Official package-manager checksum is unavailable')
            digest=base64.b64decode(integrity[7:],validate=True).hex()
            if len(digest)!=128 or (spec['pnpm'].get('source_sha512') and spec['pnpm']['source_sha512']!=digest):raise ToolchainUnavailable('Captured package-manager integrity disagrees with the official package archive')
            executable=(data.get('bin') or {}).get('pnpm')
            native={}
            if executable=='pnpm':
                dependencies=data.get('optionalDependencies') or {}
                for architecture in ('arm64','x64'):
                    package='@pnpm/exe.linux-'+architecture
                    if dependencies.get(package)!=version:raise ToolchainUnavailable('Official pnpm native package version is not exact and consistent')
                    body=await get('https://registry.npmjs.org/@pnpm%2fexe.linux-'+architecture+'/'+version)
                    entry=json.loads(body);distribution=entry.get('dist') or {}
                    url='https://registry.npmjs.org/'+package+'/-/exe.linux-'+architecture+'-'+version+'.tgz'
                    if entry.get('name')!=package or entry.get('version')!=version or entry.get('os')!=['linux'] or entry.get('cpu')!=[architecture] or distribution.get('tarball')!=url:
                        raise ToolchainUnavailable('Official pnpm native archive identity does not match the selected version and platform')
                    integrity=distribution.get('integrity','')
                    if not isinstance(integrity,str) or not integrity.startswith('sha512-'):raise ToolchainUnavailable('Official pnpm native checksum is unavailable')
                    native_digest=base64.b64decode(integrity[7:],validate=True).hex()
                    if len(native_digest)!=128:raise ToolchainUnavailable('Official pnpm native checksum is invalid')
                    native[architecture]={'url':url,'sha512':native_digest,'metadata_sha256':hashlib.sha256(body).hexdigest()}
            elif not isinstance(executable,str) or not re.fullmatch(r'bin/[A-Za-z0-9._-]+\.(?:cjs|mjs|js)',executable):
                raise ToolchainUnavailable('Official pnpm executable layout is unsupported')
            result['pnpm']={'version':version,'url':expected,'sha512':digest,'bin':executable,'native':native,'metadata_sha256':hashlib.sha256(raw).hexdigest()}
        return result
    except ToolchainUnavailable:raise
    except (httpx.HTTPError,asyncio.TimeoutError,ValueError,TypeError,KeyError,AttributeError,UnicodeError,RecursionError):
        raise ToolchainUnavailable('Official source-pinned toolchain metadata could not be verified') from None


def install_script():
    return r'''import hashlib,json,os,platform,signal,shutil,subprocess,sys,tarfile,tempfile,urllib.request
from pathlib import Path
signal.signal(signal.SIGALRM,lambda *a:(_ for _ in ()).throw(TimeoutError('LOTUS_TOOLCHAIN_DEADLINE')));signal.alarm(120)
spec=json.loads(sys.argv[1]);arch={'aarch64':'arm64','arm64':'arm64','x86_64':'x64','amd64':'x64'}.get(platform.machine().lower())
if platform.system()!='Linux' or arch not in ('arm64','x64'):raise SystemExit('LOTUS_TOOLCHAIN_PLATFORM_UNSUPPORTED')
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*a,**kw):return None
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
def install(url,digest,algorithm,dest,limit):
    with tempfile.TemporaryDirectory(prefix='lotus-toolchain-') as temp:
        archive=Path(temp)/'archive';total=0;checksum=hashlib.new(algorithm)
        with opener.open(url,timeout=30) as response,archive.open('wb') as output:
            while True:
                chunk=response.read(65536)
                if not chunk:break
                total+=len(chunk)
                if total>limit:raise SystemExit('LOTUS_TOOLCHAIN_ARCHIVE_LIMIT')
                checksum.update(chunk);output.write(chunk)
        if checksum.hexdigest()!=digest:raise SystemExit('LOTUS_TOOLCHAIN_CHECKSUM_MISMATCH')
        target=Path(dest);target.mkdir()
        with tarfile.open(archive) as tar:
            members=tar.getmembers()
            if len(members)>12000 or sum(m.size for m in members)>512*1024*1024:raise SystemExit('LOTUS_TOOLCHAIN_ARCHIVE_MEMBERS')
            roots={m.name.split('/')[0] for m in members}
            if len(roots)!=1:raise SystemExit('LOTUS_TOOLCHAIN_ARCHIVE_LAYOUT')
            tar.extractall(Path(temp)/'unpacked',filter='data')
        package=Path(temp)/'unpacked'/next(iter(roots))
        for item in package.iterdir():shutil.move(str(item),str(target/item.name))
if spec.get('node'):
    archive=spec['archives'][arch];install(archive['url'],archive['sha256'],'sha256','/opt/lotus-node',80*1024*1024)
if spec.get('pnpm'):
    package=spec['pnpm'];install(package['url'],package['sha512'],'sha512','/opt/lotus-pnpm',16*1024*1024)
    executable=Path('/opt/lotus-pnpm')/package['bin']
    if package.get('native'):
        native=package['native'][arch];install(native['url'],native['sha512'],'sha512','/opt/lotus-pnpm-native',80*1024*1024)
        executable=Path('/opt/lotus-pnpm-native/pnpm')
    bins=Path('/opt/lotus-toolchain-bin');bins.mkdir();(bins/'pnpm').symlink_to(executable)
env={'PATH':'/opt/lotus-toolchain-bin:/opt/lotus-node/bin:/usr/bin:/bin','HOME':'/tmp','COREPACK_ENABLE_NETWORK':'0'}
for command,expected in ([('/opt/lotus-node/bin/node','v'+spec['node'])] if spec.get('node') else [])+([('/opt/lotus-toolchain-bin/pnpm',spec['pnpm']['version'])] if spec.get('pnpm') else []):
    r=subprocess.run([command,'--version'],env=env,cwd='/',stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5)
    if r.returncode or r.stdout.decode().strip()!=expected:raise SystemExit('LOTUS_TOOLCHAIN_VERSION_MISMATCH')
if spec.get('go'):
    go=spec['go'];bootstrap=shutil.which('go',path='/usr/local/go/bin:/opt/go/bin:/usr/local/bin:/usr/bin:/bin')
    if not bootstrap:raise SystemExit('LOTUS_GO_BOOTSTRAP_UNAVAILABLE')
    goenv={'PATH':'/usr/local/go/bin:/usr/local/bin:/usr/bin:/bin','HOME':'/tmp','GOENV':'off',
           'GOTOOLCHAIN':'go'+go['version'],'GOPROXY':'https://proxy.golang.org','GOSUMDB':'sum.golang.org',
           'GOPRIVATE':'','GONOSUMDB':'','GONOPROXY':'','GOWORK':'off','GOPATH':'/opt/lotus-go-cache',
           'GOMODCACHE':'/opt/lotus-go-cache/pkg/mod','GOCACHE':'/tmp/lotus-go-bootstrap-cache'}
    def run_go(command,timeout):
        process=subprocess.Popen(command,env=goenv,cwd='/',stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
        try:
            stdout,stderr=process.communicate(timeout=timeout)
        except BaseException:
            try:os.killpg(process.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            process.communicate(timeout=5)
            raise
        if process.returncode or len(stdout)>4096:raise SystemExit('LOTUS_GO_VERIFIED_INSTALL_FAILED')
        return stdout.decode().strip()
    values=run_go([bootstrap,'env','GOROOT','GOVERSION'],90).splitlines()
    if len(values)!=2 or values[1]!='go'+go['version']:raise SystemExit('LOTUS_GO_VERSION_MISMATCH')
    root=Path(values[0])
    if not root.is_absolute() or not (root/'bin/go').is_file():raise SystemExit('LOTUS_GO_ROOT_INVALID')
    goenv['GOTOOLCHAIN']='local'
    expected='go version go'+go['version']+' linux/'+{'arm64':'arm64','x64':'amd64'}[arch]
    if run_go([str(root/'bin/go'),'version'],5)!=expected:raise SystemExit('LOTUS_GO_VERSION_MISMATCH')
    Path('/opt/lotus-go').symlink_to(root, target_is_directory=True)
    print('LOTUS_GO_INSTALLED: go'+go['version']+'; checksum_database=sum.golang.org; architecture='+arch)
signal.alarm(0)
print('LOTUS_TOOLCHAIN_INSTALLED: exact source versions; architecture='+arch+'; startup not tested')
'''


def recipe_lines(plan):
    if plan is None:return []
    # Rebuild every executable URL from exact validated identifiers. Stored or
    # model-mutated metadata cannot introduce an arbitrary download endpoint.
    node=_version(plan['node']) if plan.get('node') else None;archives={}
    for arch in (('arm64','x64') if node else ()):
        entry=plan['archives'][arch];url=f'https://nodejs.org/dist/v{node}/node-v{node}-linux-{arch}.tar.xz'
        if entry['url']!=url or not re.fullmatch('[a-f0-9]{64}',entry['sha256']):raise ToolchainUnavailable('Prepared Node archive identity changed')
        archives[arch]={'url':url,'sha256':entry['sha256']}
    value={'node':node,'archives':archives,'pnpm':None}
    if plan.get('go'):
        go=plan['go'];version=_version(go['version'])
        if not version.startswith('1.') or go.get('distribution')!='official-go-toolchain-module' or go.get('checksum_database')!='sum.golang.org':
            raise ToolchainUnavailable('Prepared Go distribution or checksum verification changed')
        value['go']={'version':version}
    if not node and not value.get('go'):raise ToolchainUnavailable('Prepared toolchain plan has no supported release')
    if plan.get('pnpm'):
        p=plan['pnpm'];version=_version(p['version']);url='https://registry.npmjs.org/pnpm/-/pnpm-'+version+'.tgz'
        if p['url']!=url or not re.fullmatch('[a-f0-9]{128}',p['sha512']) or not (p['bin']=='pnpm' or re.fullmatch(r'bin/[A-Za-z0-9._-]+\.(?:cjs|mjs|js)',p['bin'])):raise ToolchainUnavailable('Prepared pnpm archive identity changed')
        native={}
        if p['bin']=='pnpm':
            for arch in ('arm64','x64'):
                row=p.get('native',{}).get(arch,{})
                native_url='https://registry.npmjs.org/@pnpm/exe.linux-'+arch+'/-/exe.linux-'+arch+'-'+version+'.tgz'
                if row.get('url')!=native_url or not re.fullmatch('[a-f0-9]{128}',str(row.get('sha512',''))):raise ToolchainUnavailable('Prepared pnpm native archive identity changed')
                native[arch]={'url':native_url,'sha512':row['sha512']}
        value['pnpm']={'version':version,'url':url,'sha512':p['sha512'],'bin':p['bin'],'native':native}
    argv=['/usr/bin/env','-i','PATH=/opt/lotus-venv/bin:/usr/local/bin:/usr/bin:/bin','/opt/lotus-venv/bin/python3','-I','-c',install_script(),json.dumps(value,sort_keys=True)]
    path=('/opt/lotus-go/bin:' if value.get('go') else '')+'/opt/lotus-toolchain-bin:/opt/lotus-node/bin:/opt/lotus-venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
    return ['RUN '+json.dumps(argv),'ENV PATH='+json.dumps(path)]+(['ENV GOTOOLCHAIN=local'] if value.get('go') else [])
