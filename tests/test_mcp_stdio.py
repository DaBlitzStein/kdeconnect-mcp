import json
import select
import subprocess
import sys
import time

PROTOCOL_VERSION = "2026-07-28"


def send(proc: subprocess.Popen, payload: dict) -> None:
    proc.stdin.write(json.dumps(payload) + "\n")
    proc.stdin.flush()


def recv(proc: subprocess.Popen, wanted_id: int, timeout: float = 10.0) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        ready, _, _ = select.select([proc.stdout], [], [], max(0.05, deadline - time.time()))
        if not ready:
            continue
        line = proc.stdout.readline()
        if not line:
            break
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue
        if message.get("id") == wanted_id:
            return message
    raise AssertionError(f"Sin respuesta para id={wanted_id}")


def test_stdio_tools_list_and_call(tmp_path):
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "kdeconnect_mcp",
            "serve",
            "--fake",
            "--data-dir",
            str(tmp_path / "data"),
            "--config",
            str(tmp_path / "missing-config.yaml"),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        send(
            proc,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": "pytest", "version": "0"},
                },
            },
        )
        init = recv(proc, 1)
        assert init["result"]["serverInfo"]["name"] == "kdeconnect-mcp"
        send(proc, {"jsonrpc": "2.0", "method": "notifications/initialized"})

        send(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        tools = recv(proc, 2)["result"]["tools"]
        names = {tool["name"] for tool in tools}
        expected = {
            "get_status",
            "list_devices",
            "get_activity",
            "search_activity",
            "get_conversation",
            "get_call_log",
            "list_active_notifications",
            "acknowledge_events",
            "get_redaction_stats",
            "sync_sms_history",
            "scan_devices",
            "request_pair",
        }
        assert expected <= names

        deadline = time.time() + 5
        activity = None
        while time.time() < deadline:
            send(
                proc,
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {"name": "get_activity", "arguments": {"kind": "sms"}},
                },
            )
            result = recv(proc, 3)["result"]
            if result.get("structuredContent"):
                activity = result["structuredContent"]
            else:
                activity = json.loads(result["content"][0]["text"])
            if activity.get("count", 0) >= 2:
                break
            time.sleep(0.2)
        assert activity is not None and activity["count"] >= 2
        bodies = " ".join(event["body"] or "" for event in activity["events"])
        assert "483920" not in bodies
        assert "[REDACTADO:otp]" in bodies
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
