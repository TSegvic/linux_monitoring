import json
import signal as signal_module
import socket
import subprocess
import sys
import time
from pathlib import Path

import psutil
import requests


CONFIG_PATH = Path(__file__).with_name("agent_config.json")

DEFAULT_CONFIG = {
    "server_url": "http://192.168.1.76:5000",
    "interval":   5,
    "hostname":   socket.gethostname(),
    "description": "",
    "api_key":    None,
    "host_id":    None,
    "allow_remote_commands": True,
    "max_processes_in_list": 200,
}


# ---------- config ----------

def load_config() -> dict:
    if CONFIG_PATH.exists():
        cfg = DEFAULT_CONFIG.copy()
        cfg.update(json.loads(CONFIG_PATH.read_text()))
        return cfg
    save_config(DEFAULT_CONFIG)
    return DEFAULT_CONFIG.copy()


def save_config(cfg: dict):
    CONFIG_PATH.write_text(json.dumps(cfg, indent=2))



def register(cfg: dict) -> dict:
    """Register this host with the server and obtain an API key."""
    url = cfg["server_url"].rstrip("/") + "/api/register"
    payload = {"hostname": cfg["hostname"], "description": cfg.get("description", "")}
    r = requests.post(url, json=payload, timeout=10)
    r.raise_for_status()
    data = r.json()
    cfg["api_key"]  = data["api_key"]
    cfg["host_id"]  = data["host_id"]
    cfg["interval"] = data.get("polling_interval", cfg["interval"])
    save_config(cfg)
    print(f"[agent] Registered as host_id={cfg['host_id']}, key stored.")
    return cfg



def cmd_list_processes(payload: dict, cfg: dict) -> dict:
    """Return a list of processes sorted by CPU% descending."""
    max_n = int(cfg.get("max_processes_in_list", 200))
    procs = []

    for p in psutil.process_iter(["pid"]):
        try:
            p.cpu_percent(interval=None)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    time.sleep(0.3)  

    for p in psutil.process_iter(["pid", "name", "username", "memory_percent", "cmdline"]):
        try:
            info = p.info
            cpu  = p.cpu_percent(interval=None)
            cmdline = info.get("cmdline") or []
            procs.append({
                "pid":     info["pid"],
                "name":    info.get("name") or "?",
                "user":    info.get("username") or "?",
                "cpu":     round(cpu, 1),
                "mem":     round(info.get("memory_percent") or 0, 1),
                "cmdline": " ".join(cmdline)[:300] if cmdline else "",
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    procs.sort(key=lambda x: x["cpu"], reverse=True)
    procs = procs[:max_n]
    return {"processes": procs, "total_returned": len(procs)}


def cmd_kill_process(payload: dict, cfg: dict) -> dict:
    """Send SIGTERM or SIGKILL to a process by PID."""
    pid     = int(payload.get("pid"))
    sig     = (payload.get("signal") or "TERM").upper()
    sig_num = signal_module.SIGKILL if sig == "KILL" else signal_module.SIGTERM
    try:
        proc = psutil.Process(pid)
        name = proc.name()
        proc.send_signal(sig_num)
        try:
            proc.wait(timeout=3)
            gone = True
        except psutil.TimeoutExpired:
            gone = not proc.is_running()
        return {"killed": True, "pid": pid, "name": name, "signal": sig,
                "gone": gone,
                "message": f"sent SIG{sig} to {name} (PID {pid})"
                           + ("" if gone else "; still running after 3s")}
    except psutil.NoSuchProcess:
        return {"killed": False, "pid": pid, "message": f"PID {pid} does not exist"}
    except psutil.AccessDenied:
        return {"killed": False, "pid": pid,
                "message": f"Access denied for PID {pid} (agent lacks sufficient privileges)"}


def cmd_exec(payload: dict, cfg: dict) -> tuple:
    """Run a shell command and return (result_dict, exit_code)."""
    cmd     = payload.get("cmd", "")
    timeout = int(payload.get("timeout", 30))
    try:
        proc = subprocess.run(
            ["bash", "-c", cmd],
            capture_output=True, text=True, timeout=timeout,
        )
        return ({
            "stdout":    proc.stdout,
            "stderr":    proc.stderr,
            "exit_code": proc.returncode,
            "timeout":   False,
        }, proc.returncode)
    except subprocess.TimeoutExpired as e:
        return ({
            "stdout":    e.stdout.decode() if isinstance(e.stdout, bytes) else (e.stdout or ""),
            "stderr":    e.stderr.decode() if isinstance(e.stderr, bytes) else (e.stderr or ""),
            "exit_code": None,
            "timeout":   True,
            "error":     f"timeout after {timeout}s",
        }, -1)


COMMAND_HANDLERS = {
    "list_processes": cmd_list_processes,
    "kill_process":   cmd_kill_process,
}


def handle_command(cmd: dict, cfg: dict, base_url: str, headers: dict):
    """Execute a single command and post the result back to the server."""
    cmd_id   = cmd["id"]
    cmd_type = cmd["type"]
    payload  = cmd.get("payload") or {}
    print(f"[cmd #{cmd_id}] {cmd_type} {payload}")

    try:
        if cmd_type == "exec":
            result, exit_code = cmd_exec(payload, cfg)
            status = "done" if not result.get("timeout") else "failed"
            error  = result.get("error") if result.get("timeout") else None
            body = {"status": status, "exit_code": exit_code,
                    "result": result, "error": error}
        elif cmd_type in COMMAND_HANDLERS:
            handler = COMMAND_HANDLERS[cmd_type]
            result = handler(payload, cfg)
            body = {"status": "done", "exit_code": 0, "result": result}
        else:
            body = {"status": "failed", "error": f"unknown command type: {cmd_type}"}
    except Exception as e:
        body = {"status": "failed", "error": f"{type(e).__name__}: {e}"}

    try:
        r = requests.post(
            base_url + f"/api/commands/{cmd_id}/result",
            json=body, headers=headers, timeout=15,
        )
        if not r.ok:
            print(f"[cmd #{cmd_id}] server rejected the result: {r.status_code} {r.text[:200]}")
    except requests.RequestException as e:
        print(f"[cmd #{cmd_id}] error sending result: {e}")



class MetricsCollector:
    """Encapsulates state needed for delta computations (network counters)."""

    def __init__(self):
        self._prev_net  = psutil.net_io_counters()
        self._prev_time = time.time()
        psutil.cpu_percent(interval=None)

    def collect(self) -> dict:
        now = time.time()

        cpu_pct = psutil.cpu_percent(interval=None)
        vm      = psutil.virtual_memory()
        disk    = psutil.disk_usage("/")
        proc_n  = len(psutil.pids())
        uptime  = int(now - psutil.boot_time())

        net      = psutil.net_io_counters()
        elapsed  = max(now - self._prev_time, 0.001)
        sent_kbs = (net.bytes_sent - self._prev_net.bytes_sent) / 1024.0 / elapsed
        recv_kbs = (net.bytes_recv - self._prev_net.bytes_recv) / 1024.0 / elapsed
        self._prev_net  = net
        self._prev_time = now

        return {
            "cpu":       round(cpu_pct, 2),
            "ram":       round(vm.percent, 2),
            "disk":      round(disk.percent, 2),
            "net_sent":  round(max(sent_kbs, 0), 2),
            "net_recv":  round(max(recv_kbs, 0), 2),
            "processes": proc_n,
            "uptime":    uptime,
        }



def main():
    cfg = load_config()
    print(f"[agent] hostname = {cfg['hostname']}")
    print(f"[agent] server   = {cfg['server_url']}")

    if not cfg.get("api_key"):
        print("[agent] No API key, registering...")
        try:
            cfg = register(cfg)
        except Exception as e:
            print(f"[agent] Registration failed: {e}")
            sys.exit(1)

    metrics_url = cfg["server_url"].rstrip("/") + "/api/metrics"
    headers     = {"X-API-Key": cfg["api_key"]}
    interval    = max(int(cfg.get("interval", 5)), 1)
    collector   = MetricsCollector()

    time.sleep(1)

    while True:
        loop_start = time.time()
        try:
            data = collector.collect()
            r = requests.post(metrics_url, json=data, headers=headers, timeout=10)
            if r.status_code == 401:
                print("[agent] API key rejected, attempting to re-register...")
                cfg = register(cfg)
                headers = {"X-API-Key": cfg["api_key"]}
            elif r.ok:
                resp = r.json()
                new_interval = resp.get("polling_interval")
                if new_interval and new_interval != interval:
                    interval = max(int(new_interval), 1)
                    cfg["interval"] = interval
                    save_config(cfg)
                    print(f"[agent] Interval changed to {interval}s.")
                print(f"[sent] cpu={data['cpu']}% ram={data['ram']}% "
                      f"disk={data['disk']}% proc={data['processes']} "
                      f"net=(down {data['net_recv']}KB/s up {data['net_sent']}KB/s) "
                      f"up={data['uptime']}s")

                pending = resp.get("commands") or []
                if pending:
                    if cfg.get("allow_remote_commands", True):
                        print(f"[agent] {len(pending)} new command(s) to execute")
                        for c in pending:
                            handle_command(c, cfg,
                                           cfg["server_url"].rstrip("/"), headers)
                    else:
                        print(f"[agent] {len(pending)} command(s) refused (allow_remote_commands=false)")
                        for c in pending:
                            try:
                                requests.post(
                                    cfg["server_url"].rstrip("/") + f"/api/commands/{c['id']}/result",
                                    json={"status": "failed",
                                          "error": "allow_remote_commands is disabled in agent_config.json"},
                                    headers=headers, timeout=10,
                                )
                            except requests.RequestException:
                                pass
            else:
                print(f"[agent] Server returned {r.status_code}: {r.text[:200]}")
        except requests.RequestException as e:
            print(f"[agent] Network error: {e}")
        except Exception as e:
            print(f"[agent] Error: {e}")

        elapsed = time.time() - loop_start
        time.sleep(max(interval - elapsed, 0))


if __name__ == "__main__":
    main()
