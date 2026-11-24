"""Run the local Privacy and Safety Gateway web app."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import threading
import urllib.error
import urllib.request
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer

from benchmark import run_benchmark
from privacy_gateway import DEFAULT_POLICY, normalize_policy, scan_prompt


ROOT = Path(__file__).resolve().parent
POLICY_PATH = ROOT / "data" / "policy.local.json"
POLICY_DEFAULTS_PATH = ROOT / "data" / "policy.json"
AUDIT_PATH = ROOT / "data" / "audit.jsonl"
WEB_PATH = ROOT / "web" / "index.html"


DEFAULT_PROFILES = {
    "General": normalize_policy(DEFAULT_POLICY),
    "Academic": normalize_policy({
        **DEFAULT_POLICY,
        "known_names": ["Alex Morgan"],
        "sensitive_terms": ["exam answer key", "unpublished grades", "student record"],
    }),
    "Business": normalize_policy({
        **DEFAULT_POLICY,
        "known_names": ["Alex Morgan"],
        "sensitive_terms": ["Project Falcon", "internal roadmap", "do not share"],
    }),
}


def load_store() -> dict:
    try:
        stored = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        try:
            stored = json.loads(POLICY_DEFAULTS_PATH.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            stored = {}
    if isinstance(stored, dict) and isinstance(stored.get("profiles"), dict):
        profiles = {str(name): normalize_policy(value) for name, value in stored["profiles"].items()
                    if isinstance(value, dict)}
        if not profiles:
            profiles = {name: dict(value) for name, value in DEFAULT_PROFILES.items()}
        active = stored.get("active_profile")
        if active not in profiles:
            active = next(iter(profiles))
        return {"active_profile": active, "profiles": profiles}
    # Migrate a single-policy file from an earlier project version.
    profiles = {name: dict(value) for name, value in DEFAULT_PROFILES.items()}
    if isinstance(stored, dict) and stored:
        profiles["General"] = normalize_policy(stored)
    return {"active_profile": "General", "profiles": profiles}


def active_profile() -> str:
    return load_store()["active_profile"]


def load_policy() -> dict:
    store = load_store()
    return store["profiles"][store["active_profile"]]


def save_policy(policy: dict) -> dict:
    cleaned = normalize_policy(policy)
    store = load_store()
    store["profiles"][store["active_profile"]] = cleaned
    POLICY_PATH.parent.mkdir(parents=True, exist_ok=True)
    POLICY_PATH.write_text(json.dumps(store, indent=2), encoding="utf-8")
    return cleaned


def activate_profile(profile: str) -> dict:
    store = load_store()
    if profile not in store["profiles"]:
        raise ValueError("Select an available policy profile.")
    store["active_profile"] = profile
    POLICY_PATH.parent.mkdir(parents=True, exist_ok=True)
    POLICY_PATH.write_text(json.dumps(store, indent=2), encoding="utf-8")
    return store


def add_audit(event: dict) -> None:
    """Store action metadata and optional protected text, not a separate raw-input field."""
    AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
    record = {"time": datetime.now(timezone.utc).isoformat(timespec="seconds"), **event}
    with AUDIT_PATH.open("a", encoding="utf-8") as audit_file:
        audit_file.write(json.dumps(record, ensure_ascii=False) + "\n")


def read_audit(limit: int = 30) -> list[dict]:
    try:
        lines = AUDIT_PATH.read_text(encoding="utf-8").splitlines()[-limit:]
    except OSError:
        return []
    records = []
    for line in reversed(lines):
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return records


def send_to_demo(protected_prompt: str) -> dict:
    return {
        "provider": "Local demo model",
        "response": ("The prompt passed through the local privacy gateway. "
                     f"The demo service received {len(protected_prompt)} protected characters."),
    }


def send_to_api(protected_prompt: str, model: str) -> dict:
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY is not set. Add it to this terminal session and restart the app.")
    body = json.dumps({
        "model": model,
        "messages": [{"role": "user", "content": protected_prompt}],
    }).encode("utf-8")
    request = urllib.request.Request(
        "https://api.openai.com/v1/chat/completions",
        data=body,
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=45) as response:
            result = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        message = error.read().decode("utf-8", errors="replace")[:500]
        raise RuntimeError(f"AI service returned HTTP {error.code}: {message}") from error
    except urllib.error.URLError as error:
        raise RuntimeError(f"Could not reach AI service: {error.reason}") from error
    answer = result.get("choices", [{}])[0].get("message", {}).get("content", "No text response returned.")
    return {"provider": f"OpenAI API ({model})", "response": answer}


class GatewayHandler(BaseHTTPRequestHandler):
    server_version = "PrivacyGateway/1.0"

    def log_message(self, fmt: str, *args) -> None:
        # Keep terminal output clear and avoid printing prompt-related request data.
        print(f"[{self.log_date_time_string()}] {fmt % args}")

    def _json(self, data: dict, status: int = 200) -> None:
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        if length > 100_000:
            raise ValueError("Request is too large (maximum 100 KB).")
        return json.loads(self.rfile.read(length).decode("utf-8"))

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler method name
        if self.path in ("/", "/index.html"):
            try:
                content = WEB_PATH.read_bytes()
            except OSError:
                self.send_error(500, "web/index.html is missing")
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(content)
        elif self.path == "/api/policy":
            store = load_store()
            self._json({"policy": load_policy(), "profiles": list(store["profiles"]),
                        "active_profile": store["active_profile"],
                        "live_enabled": self.server.live_enabled, "model": self.server.model})
        elif self.path == "/api/audit":
            self._json({"records": read_audit()})
        elif self.path == "/api/benchmark":
            self._json(run_benchmark(load_policy()))
        else:
            self.send_error(404)

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler method name
        try:
            payload = self._body()
            if self.path == "/api/analyze":
                prompt = payload.get("prompt", "")
                if not isinstance(prompt, str) or not prompt.strip():
                    raise ValueError("Enter a prompt to analyze.")
                policy = load_policy()
                result = scan_prompt(prompt, policy)
                add_audit({
                    "status": "ANALYZED", "provider": "LOCAL_SCAN",
                    "prompt_length": len(prompt), "input_length": len(prompt),
                    "protected_length": result["protected_length"],
                    "protected_prompt": result["protected_prompt"] if policy["store_protected_prompts"] else None,
                    "categories": [finding["category"] for finding in result["findings"]],
                    "actions": [f"{finding['category']}:{finding['action']}" for finding in result["findings"]],
                    "findings": [{key: finding[key] for key in ("category", "action", "start", "end", "suspicious")}
                                 for finding in result["findings"]],
                    "injection_detected": result["injection_detected"], "policy_profile": active_profile(),
                })
                self._json(result)
            elif self.path == "/api/policy":
                policy = save_policy(payload)
                self._json({"policy": policy, "message": "Policy saved on this computer."})
            elif self.path == "/api/profile":
                store = activate_profile(payload.get("profile", ""))
                self._json({"policy": store["profiles"][store["active_profile"]],
                            "active_profile": store["active_profile"], "message": "Policy profile switched."})
            elif self.path == "/api/send":
                self._send_reviewed_prompt(payload)
            else:
                self.send_error(404)
        except (ValueError, TypeError, json.JSONDecodeError) as error:
            self._json({"error": str(error)}, 400)
        except RuntimeError as error:
            self._json({"error": str(error)}, 502)

    def _send_reviewed_prompt(self, payload: dict) -> None:
        policy = load_policy()
        original_prompt = payload.get("prompt")
        if not isinstance(original_prompt, str) or not original_prompt.strip():
            raise ValueError("Analyze and review a prompt before sending.")
        # Re-scan on the server so a modified browser request cannot bypass policy.
        fresh_scan = scan_prompt(original_prompt, policy)
        protected = fresh_scan["protected_prompt"]
        injection_detected = fresh_scan["injection_detected"]
        override = bool(payload.get("override_injection"))
        if injection_detected and policy["block_prompt_injection"] and not override:
            categories = [finding["category"] for finding in fresh_scan["findings"]]
            add_audit({
                "status": "BLOCKED", "provider": "POLICY", "prompt_length": len(protected),
                "input_length": len(original_prompt), "protected_length": len(protected),
                "protected_prompt": protected if policy["store_protected_prompts"] else None,
                "categories": categories,
                "actions": [f"{finding['category']}:{finding['action']}" for finding in fresh_scan["findings"]],
                "findings": [{key: finding[key] for key in ("category", "action", "start", "end", "suspicious")}
                             for finding in fresh_scan["findings"]],
                "injection_detected": True,
                "injection_override": False, "policy_profile": active_profile(),
            })
            self._json({"error": "Policy blocked this suspicious prompt. Review it and explicitly allow it once to continue."}, 403)
            return
        provider = payload.get("provider", "demo")
        categories = [str(item.get("category", "UNKNOWN")) for item in fresh_scan["findings"]]
        if provider == "live" and not self.server.live_enabled:
            raise ValueError("Live mode is off. Restart the app with --live to enable it.")
        try:
            result = send_to_api(protected, self.server.model) if provider == "live" else send_to_demo(protected)
        except RuntimeError:
            add_audit({
                "status": "FAILED", "provider": provider, "prompt_length": len(protected),
                "input_length": len(original_prompt), "protected_length": len(protected),
                "protected_prompt": protected if policy["store_protected_prompts"] else None,
                "categories": categories,
                "actions": [f"{finding['category']}:{finding['action']}" for finding in fresh_scan["findings"]],
                "findings": [{key: finding[key] for key in ("category", "action", "start", "end", "suspicious")}
                             for finding in fresh_scan["findings"]],
                "injection_detected": injection_detected,
                "injection_override": override, "policy_profile": active_profile(),
            })
            raise
        add_audit({
            "status": "SENT", "provider": result["provider"], "prompt_length": len(protected),
            "input_length": len(original_prompt), "protected_length": len(protected),
            "protected_prompt": protected if policy["store_protected_prompts"] else None,
            "categories": categories,
            "actions": [f"{finding['category']}:{finding['action']}" for finding in fresh_scan["findings"]],
            "findings": [{key: finding[key] for key in ("category", "action", "start", "end", "suspicious")}
                         for finding in fresh_scan["findings"]],
            "injection_detected": injection_detected,
            "injection_override": override, "policy_profile": active_profile(),
        })
        self._json(result)


def main() -> None:
    parser = argparse.ArgumentParser(description="Local privacy gateway for AI prompts")
    parser.add_argument("--port", type=int, default=8000, help="Local web server port (default: 8000)")
    parser.add_argument("--live", action="store_true", help="Enable optional OpenAI API forwarding")
    parser.add_argument("--model", default="gpt-4o-mini", help="Model name for --live mode")
    parser.add_argument("--no-browser", action="store_true", help="Do not open a browser automatically")
    args = parser.parse_args()
    try:
        server = HTTPServer(("127.0.0.1", args.port), GatewayHandler)
    except OSError as error:
        parser.exit(1, f"Could not start the gateway on port {args.port}. "
                   f"Try 'python app.py --port 8001'. Details: {error}\n")
    server.live_enabled = args.live
    server.model = args.model
    url = f"http://127.0.0.1:{args.port}"
    print("Privacy and Safety Gateway is running locally.")
    print(f"Opening {url} in your browser.")
    print("Prompts are analyzed locally. Press Ctrl+C to stop.")
    if not args.no_browser:
        threading.Timer(0.8, webbrowser.open, args=(url,)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nGateway stopped.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
