import os
import re
import httpx

# Default channel for bot token messages (user can override via env)
SLACK_CHANNEL = os.environ.get("LOTUS_SLACK_CHANNEL", "#security-alerts")


def public_base_url() -> str:
    """Base URL used to build clickable permalinks back into the platform UI."""
    return (os.environ.get("LOTUS_PUBLIC_URL")
            or os.environ.get("LOTUS_BASE_URL")
            or "http://localhost:8000").rstrip("/")


def repo_short_name(source: str) -> str:
    """Short, privacy-preserving repo name (never leak the full clone URL to Slack)."""
    s = (source or "").strip().rstrip("/")
    s = re.sub(r"\.git$", "", s)
    name = s.split("/")[-1] if "/" in s else s
    # For a local path, keep just the final component.
    name = name.split(os.sep)[-1] if os.sep in name else name
    return name or "repository"


def _sev_label(cvss: float) -> str:
    if cvss >= 9.0:
        return "CRITICAL"
    if cvss >= 7.0:
        return "HIGH"
    if cvss >= 4.0:
        return "MEDIUM"
    return "LOW"


def format_scan_complete(
    *,
    repo_source: str,
    branch: str = "main",
    repo_id: int,
    duration_s: float,
    raw_leads: int,
    confirmed: int,
    qualified: int,
    findings: list,
    report_id=None,
) -> str:
    """Compose a rich Slack message for a completed scan.

    - Uses only the repo SHORT NAME (never the full clone URL).
    - Puts the key scan stats in a code block.
    - Lists each report-eligible finding with severity and a clickable permalink back
      to the report/finding on the platform.

    `findings` is a list of dicts/objects exposing id, title, cvss, status.
    """
    base = public_base_url()
    short = repo_short_name(repo_source)

    crit = sum(1 for f in findings if _get(f, "cvss", 0) >= 9.0)
    high = sum(1 for f in findings if 7.0 <= _get(f, "cvss", 0) < 9.0)
    med = sum(1 for f in findings if 4.0 <= _get(f, "cvss", 0) < 7.0)

    lines = [f":mag: *Lotus scan complete — {short}* (`{branch}`)", ""]
    stats = (
        "```\n"
        f"Duration : {duration_s:.1f}s\n"
        f"Raw leads: {raw_leads}\n"
        f"Confirmed: {confirmed}\n"
        f"Qualified: {qualified}\n"
        f"Severity : {crit} critical, {high} high, {med} medium\n"
        "```"
    )
    lines.append(stats)

    if findings:
        lines.append("*Report-eligible findings:*")
        for f in findings[:15]:
            fid = _get(f, "id", None)
            title = str(_get(f, "title", "finding"))[:120]
            cvss = _get(f, "cvss", 0)
            sev = _sev_label(cvss)
            if fid is not None:
                # Deep link opens the finding notebook (repro-on-lab + verify).
                link = finding_permalink(fid)
                lines.append(f"• `[{sev} {cvss}]` <{link}|{title}>")
            else:
                lines.append(f"• `[{sev} {cvss}]` {title}")
        if len(findings) > 15:
            lines.append(f"…and {len(findings) - 15} more")
    else:
        lines.append("_No report-eligible findings above the CVSS threshold._")

    # Permalink to open the full report notebook, or (if no report exists yet)
    # this repo's report-eligible findings list on the platform.
    if report_id is not None:
        lines.append(f"\n:page_facing_up: <{report_permalink(report_id)}|Open the full report notebook>")
    else:
        lines.append(f"\n:page_facing_up: <{repo_findings_permalink(repo_id)}|Open the findings on the platform>")
    return "\n".join(lines)


def finding_permalink(finding_id) -> str:
    """Permalink that opens the finding notebook (repro-on-lab + verify)."""
    return f"{public_base_url()}/?finding={finding_id}#findings"


def report_permalink(report_id) -> str:
    """Permalink that opens the full report notebook."""
    return f"{public_base_url()}/?report={report_id}#reports"


def repo_findings_permalink(repo_id) -> str:
    """Permalink to a repo's report-eligible findings list."""
    return f"{public_base_url()}/?repo={repo_id}#findings"


def _get(obj, key, default=None):
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def send_slack_with_details(webhook_or_token: str, text: str, channel: str = None) -> tuple[bool, str]:
    """Send a message to Slack and return (success, error_message).

    If the value starts with 'xoxb-', it uses the Slack Web API (chat.postMessage)
    which requires the bot to have chat:write scope. Otherwise, treats it as an
    incoming webhook URL.
    """
    if not webhook_or_token or not webhook_or_token.strip():
        return False, "No Slack webhook URL or bot token configured"

    val = webhook_or_token.strip()
    if "•" in val or "***" in val:
        return False, "Configured token is masked. Please re-enter your bot token or webhook URL."

    try:
        if val.startswith("xoxb-"):
            target_chan = (channel or SLACK_CHANNEL).strip()
            # Bot token: use Slack Web API chat.postMessage
            r = httpx.post(
                "https://slack.com/api/chat.postMessage",
                headers={
                    "Authorization": f"Bearer {val}",
                    "Content-Type": "application/json; charset=utf-8",
                },
                json={"channel": target_chan, "text": text},
                timeout=10,
            )
            try:
                data = r.json()
            except Exception:
                data = {}

            if r.status_code == 200 and data.get("ok", False):
                return True, ""
            err_code = data.get("error", f"HTTP {r.status_code}")
            if err_code == "not_in_channel":
                clean_name = target_chan.lstrip("#")
                return False, f"Bot is not in channel '{target_chan}'. In Slack, go to #{clean_name} and invite the bot by typing: /invite @notify"
            elif err_code == "channel_not_found":
                return False, f"Channel '{target_chan}' not found in your Slack workspace. Check the channel name or use channel ID."
            elif err_code == "invalid_auth":
                return False, "Invalid Slack bot token. Check your xoxb token."
            elif err_code == "account_inactive":
                return False, "Slack account or token is inactive/revoked."
            return False, f"Slack API error: {err_code}"
        else:
            # Incoming webhook URL
            # Revalidate at the network boundary as defense in depth for
            # restored/legacy settings or direct callers.  In shared
            # deployments this prevents notification delivery becoming an
            # SSRF primitive; local single-user profiles may still use a
            # local Slack-compatible endpoint.
            try:
                from backend.validation import validate_outbound_http_url
                val = validate_outbound_http_url(val, field_name="slack_webhook_url")
            except Exception as exc:
                return False, str(exc)
            r = httpx.post(val, json={"text": text}, timeout=10)
            if r.status_code < 400:
                return True, ""
            return False, f"Webhook returned HTTP {r.status_code}: {r.text[:100]}"
    except httpx.ConnectError:
        return False, "Network error: Unable to connect to Slack servers"
    except httpx.TimeoutException:
        return False, "Network error: Connection to Slack timed out"
    except Exception as e:
        return False, f"Slack error: {str(e)[:150]}"


def send_slack(webhook_or_token: str, text: str, channel: str = None) -> bool:
    """Send a message to Slack via webhook URL or bot token (xoxb-).

    Maintains backward-compatible boolean return.
    """
    ok, _ = send_slack_with_details(webhook_or_token, text, channel=channel)
    return ok
