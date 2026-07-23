#!/usr/bin/env python3
"""
ZAP API client for kali-ai offensive-security agents.

Provides a simple interface to OWASP ZAP running in daemon mode.
Usage: python3 /tools/zap_client.py <command> [args]
"""

import json
import sys
import time
import urllib.request
import urllib.parse
import urllib.error

ZAP_HOST = "http://zap:8090"
TIMEOUT = 300


def _call(endpoint: str, params: dict = None) -> dict:
    """Call ZAP API endpoint and return JSON response."""
    url = f"{ZAP_HOST}/JSON/{endpoint}"
    if params:
        url += "?" + urllib.parse.urlencode(params)
    try:
        with urllib.request.urlopen(url, timeout=TIMEOUT) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.URLError as e:
        return {"error": str(e)}


def status() -> dict:
    """Check if ZAP is running."""
    return _call("core/view/version")


def new_session(name: str = None) -> dict:
    """Create a new ZAP session."""
    params = {"name": name} if name else {}
    return _call("core/action/newSession", params)


def spider(url: str, max_children: int = None) -> dict:
    """Start spidering a target URL."""
    params = {"url": url}
    if max_children:
        params["maxChildren"] = str(max_children)
    return _call("spider/action/scan", params)


def spider_status(scan_id: str) -> dict:
    """Get spider progress."""
    return _call("spider/view/status", {"scanId": scan_id})


def ajax_spider(url: str, in_scope: bool = True) -> dict:
    """Start AJAX spider (for JavaScript-heavy apps)."""
    return _call("ajaxSpider/action/scan", {"url": url, "inScope": str(in_scope).lower()})


def ajax_spider_status() -> dict:
    """Get AJAX spider status."""
    return _call("ajaxSpider/view/status")


def active_scan(url: str, recurse: bool = True, in_scope_only: bool = True) -> dict:
    """Start active scan on a target."""
    return _call("ascan/action/scan", {
        "url": url,
        "recurse": str(recurse).lower(),
        "inScopeOnly": str(in_scope_only).lower(),
    })


def active_scan_status(scan_id: str) -> dict:
    """Get active scan progress."""
    return _call("ascan/view/status", {"scanId": scan_id})


def alerts(base_url: str = None, start: int = 0, count: int = 100) -> dict:
    """Get alerts (findings)."""
    params = {"start": str(start), "count": str(count)}
    if base_url:
        params["baseurl"] = base_url
    return _call("core/view/alerts", params)


def alert_summary(base_url: str = None) -> dict:
    """Get alert summary by risk level."""
    params = {}
    if base_url:
        params["baseurl"] = base_url
    return _call("alert/view/alertsByRisk", params)


def html_report() -> str:
    """Generate HTML report."""
    url = f"{ZAP_HOST}/OTHER/core/other/htmlreport"
    with urllib.request.urlopen(url, timeout=TIMEOUT) as resp:
        return resp.read().decode()


def urls(base_url: str = None) -> dict:
    """Get discovered URLs."""
    params = {}
    if base_url:
        params["baseurl"] = base_url
    return _call("core/view/urls", params)


def proxy_history(start: int = 0, count: int = 100) -> dict:
    """Get proxy history."""
    return _call("core/view/messages", {"start": str(start), "count": str(count)})


def send_request(request: str, follow_redirects: bool = True) -> dict:
    """Send a custom HTTP request through ZAP."""
    return _call("core/action/sendRequest", {
        "request": request,
        "followRedirects": str(follow_redirects).lower(),
    })


def break_request(url: str, state: bool = True) -> dict:
    """Set break point on a URL."""
    return _call("break/action/break", {
        "type": "http-all",
        "state": str(state).lower(),
        "scope": "site",
        "url": url,
    })


def replacer_add(description: str, enabled: bool, match_type: str, match_string: str, replacement: str) -> dict:
    """Add a replacer rule (modify requests/responses on the fly)."""
    return _call("replacer/action/addRule", {
        "description": description,
        "enabled": str(enabled).lower(),
        "matchType": match_type,
        "matchString": match_string,
        "replacement": replacement,
    })


def replacer_list() -> dict:
    """List replacer rules."""
    return _call("replacer/view/rules")


def forced_user(user_id: str) -> dict:
    """Set forced user for authentication testing."""
    return _call("forcedUser/action/setForcedUser", {"userId": user_id})


def auth_method(context_id: str, method: str, params: dict) -> dict:
    """Set authentication method for a context."""
    p = {"contextId": context_id, "authMethodName": method}
    p.update(params)
    return _call("authentication/action/setAuthenticationMethod", p)


def scan_policy_add(name: str, alert_threshold: str = "Medium", attack_strength: str = "Medium") -> dict:
    """Add a custom scan policy."""
    return _call("ascan/action/addScanPolicy", {
        "scanPolicyName": name,
        "alertThreshold": alert_threshold,
        "attackStrength": attack_strength,
    })


def wait_for_spider(scan_id: str, timeout: int = 300) -> bool:
    """Wait for spider to complete."""
    start = time.time()
    while time.time() - start < timeout:
        result = spider_status(scan_id)
        if result.get("status") == "100":
            return True
        time.sleep(2)
    return False


def wait_for_ajax_spider(timeout: int = 600) -> bool:
    """Wait for AJAX spider to complete."""
    start = time.time()
    while time.time() - start < timeout:
        result = ajax_spider_status()
        if result.get("status") == "stopped":
            return True
        time.sleep(5)
    return False


def wait_for_active_scan(scan_id: str, timeout: int = 600) -> bool:
    """Wait for active scan to complete."""
    start = time.time()
    while time.time() - start < timeout:
        result = active_scan_status(scan_id)
        if result.get("status") == "100":
            return True
        time.sleep(5)
    return False


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1]
    args = sys.argv[2:]

    if cmd == "status":
        print(json.dumps(status(), indent=2))
    elif cmd == "new-session":
        name = args[0] if args else None
        print(json.dumps(new_session(name), indent=2))
    elif cmd == "spider":
        if not args:
            print("Usage: zap_client.py spider <url> [max_children]")
            sys.exit(1)
        max_children = int(args[1]) if len(args) > 1 else None
        print(json.dumps(spider(args[0], max_children), indent=2))
    elif cmd == "spider-status":
        if not args:
            print("Usage: zap_client.py spider-status <scan_id>")
            sys.exit(1)
        print(json.dumps(spider_status(args[0]), indent=2))
    elif cmd == "ajax-spider":
        if not args:
            print("Usage: zap_client.py ajax-spider <url>")
            sys.exit(1)
        print(json.dumps(ajax_spider(args[0]), indent=2))
    elif cmd == "ajax-spider-status":
        print(json.dumps(ajax_spider_status(), indent=2))
    elif cmd == "scan":
        if not args:
            print("Usage: zap_client.py scan <url>")
            sys.exit(1)
        print(json.dumps(active_scan(args[0]), indent=2))
    elif cmd == "scan-status":
        if not args:
            print("Usage: zap_client.py scan-status <scan_id>")
            sys.exit(1)
        print(json.dumps(active_scan_status(args[0]), indent=2))
    elif cmd == "alerts":
        base_url = args[0] if args else None
        print(json.dumps(alerts(base_url), indent=2))
    elif cmd == "alert-summary":
        base_url = args[0] if args else None
        print(json.dumps(alert_summary(base_url), indent=2))
    elif cmd == "urls":
        base_url = args[0] if args else None
        print(json.dumps(urls(base_url), indent=2))
    elif cmd == "history":
        print(json.dumps(proxy_history(), indent=2))
    elif cmd == "report":
        print(html_report())
    elif cmd == "wait-spider":
        if not args:
            print("Usage: zap_client.py wait-spider <scan_id>")
            sys.exit(1)
        print("completed" if wait_for_spider(args[0]) else "timeout")
    elif cmd == "wait-ajax-spider":
        print("completed" if wait_for_ajax_spider() else "timeout")
    elif cmd == "wait-scan":
        if not args:
            print("Usage: zap_client.py wait-scan <scan_id>")
            sys.exit(1)
        print("completed" if wait_for_active_scan(args[0]) else "timeout")
    else:
        print(f"Unknown command: {cmd}")
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
