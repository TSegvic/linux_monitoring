import os
import sys
import tempfile

import database as db
db.DB_PATH = os.path.join(tempfile.mkdtemp(), "test.db")

import server
from services import (HostService, MetricsService, ThresholdService,
                      AlertService, CommandService, ValidationError)

_failures = 0


def check(condition, message):
    global _failures
    if condition:
        print("PASS - " + message)
    else:
        _failures += 1
        print("FAIL - " + message)


def main():
    db.init_db()
    server.app.config["TESTING"] = True
    client = server.app.test_client()

    r = client.post("/api/register", json={"hostname": "vm-test", "description": "ci"})
    check(r.status_code == 201, "agent registration returns 201")
    key = r.get_json()["api_key"]
    host_id = r.get_json()["host_id"]

    r = client.post("/api/metrics", headers={"X-API-Key": key},
                    json={"cpu": 150, "ram": -5, "disk": 99,
                          "net_sent": -10, "processes": 200, "uptime": 3600})
    check(r.status_code == 200, "metric submission accepted")

    latest = MetricsService.history(host_id, "1h")[-1]
    check(latest["cpu"] == 100.0, "cpu of 150 is clamped to 100")
    check(latest["ram"] == 0.0, "ram of -5 is clamped to 0")
    check(latest["net_sent"] == 0.0, "negative net_sent is floored to 0")

    check(any(a["metric"] == "cpu" and a["level"] == "critical"
              for a in AlertService.list(host_id=host_id)),
          "critical CPU alert raised when value crosses the limit")

    check(client.post("/api/metrics", headers={"X-API-Key": "bogus"},
                      json={}).status_code == 401,
          "invalid API key is rejected with 401")

    try:
        ThresholdService.save("cpu", warning=90, critical=80)
        check(False, "warning >= critical must be rejected")
    except ValidationError:
        check(True, "warning >= critical is rejected")

    try:
        CommandService.request_kill(host_id, pid=1, signal="TERM", issued_by="t")
        check(False, "killing PID 1 must be rejected")
    except ValidationError:
        check(True, "killing PID <= 1 is rejected")

    try:
        CommandService.request_exec(host_id, cmd="  ", timeout=30, issued_by="t")
        check(False, "empty command must be rejected")
    except ValidationError:
        check(True, "empty exec command is rejected")

    cid = CommandService.request_exec(host_id, cmd="uname -a", timeout=99999, issued_by="t")
    check(db.get_command(cid)["payload"]["timeout"] == 600,
          "oversized exec timeout is clamped to 600")

    CommandService.request_process_list(host_id, "t")
    check(CommandService.request_process_list(host_id, "t") is None,
          "duplicate refresh request is debounced")

    handed = client.post("/api/metrics", headers={"X-API-Key": key},
                         json={"cpu": 1, "ram": 1, "disk": 1}).get_json()
    check(len(handed["commands"]) >= 1, "pending commands are handed to the agent")

    host = next(h for h in HostService.list_with_status() if h["id"] == host_id)
    check(host["online"] is True, "a freshly seen host reports as online")

    print()
    if _failures:
        print(f"{_failures} check(s) failed.")
        sys.exit(1)
    print("All checks passed.")


if __name__ == "__main__":
    main()
