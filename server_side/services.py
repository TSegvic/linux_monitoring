

from datetime import datetime, timedelta

import database as db




MIN_POLLING_INTERVAL = 1
MAX_POLLING_INTERVAL = 3600

PCT_MIN = 0.0
PCT_MAX = 100.0

ALLOWED_COMMAND_TYPES = ("list_processes", "kill_process", "exec")
ALLOWED_KILL_SIGNALS = ("TERM", "KILL")
MIN_EXEC_TIMEOUT = 1
MAX_EXEC_TIMEOUT = 600

RANGE_TO_HOURS = {"1h": 1, "6h": 6, "24h": 24, "7d": 24 * 7}
DEFAULT_RANGE = "1h"
MAX_METRIC_POINTS = 5000

ONLINE_MIN_SECONDS = 15
OFFLINE_MIN_SECONDS = 30
OFFLINE_MULTIPLIER = 3


class ValidationError(ValueError):
    """Raised when input violates a business rule. The routes catch this and
    turn it into a flash message or an HTTP 400 response."""


def _clamp(value, low, high):
    return max(low, min(high, value))


def _coerce_float(value, field):
    try:
        return float(value)
    except (TypeError, ValueError):
        raise ValidationError(f"{field} must be a number")


def _coerce_int(value, field):
    try:
        return int(value)
    except (TypeError, ValueError):
        raise ValidationError(f"{field} must be a whole number")




class HostService:
    """Domain rules about monitored machines: registration, online status and
    configuration limits."""

    @staticmethod
    def register(hostname, description=""):
        hostname = (hostname or "").strip()
        if not hostname:
            raise ValidationError("hostname is required")
        if len(hostname) > 255:
            raise ValidationError("hostname is too long (max 255 characters)")
        return db.register_host(hostname, (description or "").strip())

    @staticmethod
    def is_online(host):
        """A host is online if its most recent report is newer than
        OFFLINE_MULTIPLIER * polling_interval seconds, with a floor so very
        short intervals do not flap between states."""
        last_seen = host.get("last_seen")
        if not last_seen:
            return False
        window = max(ONLINE_MIN_SECONDS, host["polling_interval"] * OFFLINE_MULTIPLIER)
        age = (datetime.utcnow() - datetime.fromisoformat(last_seen)).total_seconds()
        return age < window

    @staticmethod
    def list_with_status():
        """Every host plus its latest metric and a computed online flag."""
        hosts = db.list_hosts()
        for h in hosts:
            h["online"] = HostService.is_online(h)
        return hosts

    @staticmethod
    def get(host_id):
        return db.get_host(host_id)

    @staticmethod
    def update_config(host_id, polling_interval=None, active=None, description=None):
        if polling_interval is not None:
            polling_interval = _clamp(
                _coerce_int(polling_interval, "polling_interval"),
                MIN_POLLING_INTERVAL, MAX_POLLING_INTERVAL,
            )
        db.update_host_config(
            host_id,
            polling_interval=polling_interval,
            active=active,
            description=description,
        )

    @staticmethod
    def delete(host_id):
        db.delete_host(host_id)




class MetricsService:
    """Rules for accepting, normalising and querying time-series metrics."""

    @staticmethod
    def normalize(payload):
        """Turn a raw agent payload into a clean record. Percentages are clamped
        to 0..100; counters that can never be negative are floored at 0. This
        protects the database and the charts from a misbehaving or hostile
        agent."""
        payload = payload or {}
        return {
            "cpu":       _clamp(_coerce_float(payload.get("cpu", 0), "cpu"), PCT_MIN, PCT_MAX),
            "ram":       _clamp(_coerce_float(payload.get("ram", 0), "ram"), PCT_MIN, PCT_MAX),
            "disk":      _clamp(_coerce_float(payload.get("disk", 0), "disk"), PCT_MIN, PCT_MAX),
            "net_sent":  max(_coerce_float(payload.get("net_sent", 0), "net_sent"), 0.0),
            "net_recv":  max(_coerce_float(payload.get("net_recv", 0), "net_recv"), 0.0),
            "processes": max(_coerce_int(payload.get("processes", 0), "processes"), 0),
            "uptime":    max(_coerce_int(payload.get("uptime", 0), "uptime"), 0),
        }

    @staticmethod
    def ingest(host, payload):
        """Full ingestion pipeline for one metric submission: normalise, store,
        update the host's last-seen timestamp and evaluate alerts."""
        record = MetricsService.normalize(payload)
        db.insert_metric(host["id"], record)
        db.update_host_seen(host["id"])
        AlertService.evaluate_metric(host["id"], host["hostname"], record)
        return record

    @staticmethod
    def range_to_since(range_str):
        """Map a UI range token (1h, 6h, 24h, 7d) to an absolute UTC cutoff."""
        hours = RANGE_TO_HOURS.get(range_str, RANGE_TO_HOURS[DEFAULT_RANGE])
        return datetime.utcnow() - timedelta(hours=hours)

    @staticmethod
    def history(host_id, range_str=DEFAULT_RANGE, limit=500):
        limit = _clamp(_coerce_int(limit, "limit"), 1, MAX_METRIC_POINTS)
        since = MetricsService.range_to_since(range_str)
        return db.get_metrics(host_id, since=since, limit=limit)




class ThresholdService:
    """Validation and retrieval of alert thresholds."""

    @staticmethod
    def get(host_id=None):
        return db.get_thresholds(host_id)

    @staticmethod
    def save(metric, warning, critical, host_id=None):
        warning = _clamp(_coerce_float(warning, f"{metric} warning"), PCT_MIN, PCT_MAX)
        critical = _clamp(_coerce_float(critical, f"{metric} critical"), PCT_MIN, PCT_MAX)
        if warning >= critical:
            raise ValidationError(
                f"{metric.upper()}: warning ({warning:.0f}%) must be lower than "
                f"critical ({critical:.0f}%)"
            )
        db.set_threshold(metric, warning, critical, host_id=host_id)


class AlertService:
    """The alerting policy: deciding when a metric or an absent host warrants an
    alert. The actual storage and de-duplication are handled by database.py;
    the decision of warning-vs-critical-vs-nothing is made here."""

    METRIC_LABELS = {"cpu": "CPU usage", "ram": "RAM usage", "disk": "Disk usage"}

    @staticmethod
    def evaluate_metric(host_id, hostname, record):
        """Compare a freshly stored metric against the effective thresholds and
        raise warning or critical alerts where the value crosses a limit."""
        thresholds = db.get_thresholds(host_id)
        for metric, label in AlertService.METRIC_LABELS.items():
            t = thresholds.get(metric)
            if not t:
                continue
            value = record.get(metric, 0)
            level = AlertService._level_for(value, t)
            if level is None:
                continue
            limit = t[level]
            db.insert_alert(
                host_id, metric, level,
                f"{label} on {hostname} = {value:.1f}% ({level} >= {limit}%)",
                value=value, threshold=limit,
            )

    @staticmethod
    def _level_for(value, threshold):
        if value >= threshold["critical"]:
            return "critical"
        if value >= threshold["warning"]:
            return "warning"
        return None

    @staticmethod
    def check_offline_hosts():
        """Raise a critical alert for any active host that has gone silent for
        longer than its offline window."""
        now = datetime.utcnow()
        for h in db.list_hosts():
            if not h["active"] or not h["last_seen"]:
                continue
            window = max(OFFLINE_MIN_SECONDS, h["polling_interval"] * OFFLINE_MULTIPLIER)
            silent_for = (now - datetime.fromisoformat(h["last_seen"])).total_seconds()
            if silent_for > window:
                db.insert_alert(
                    h["id"], "offline", "critical",
                    f"Host {h['hostname']} is unreachable (last seen {h['last_seen']} UTC)",
                )

    @staticmethod
    def list(host_id=None, only_unresolved=False, limit=200):
        return db.list_alerts(host_id=host_id, only_unresolved=only_unresolved, limit=limit)

    @staticmethod
    def resolve(alert_id):
        db.resolve_alert(alert_id)




class CommandService:
    """The rules around queuing remote commands for an agent: what is allowed,
    how arguments are validated, and how results are authorised when they come
    back."""

    @staticmethod
    def request_process_list(host_id, issued_by):
        """Queue a list_processes command, but only if one is not already
        waiting. Without this guard the dashboard's auto-refresh could pile up
        dozens of identical requests faster than the agent can answer them."""
        for c in db.list_commands(host_id, limit=5, types=["list_processes"]):
            if c["status"] in ("pending", "executing"):
                return None
        return db.queue_command(host_id, "list_processes", {}, issued_by)

    @staticmethod
    def request_kill(host_id, pid, signal, issued_by):
        pid = _coerce_int(pid, "pid")
        if pid <= 1:
            raise ValidationError("refusing to signal PID <= 1 (init / kernel)")
        signal = (signal or "TERM").upper()
        if signal not in ALLOWED_KILL_SIGNALS:
            raise ValidationError(f"signal must be one of {ALLOWED_KILL_SIGNALS}")
        return db.queue_command(host_id, "kill_process",
                                {"pid": pid, "signal": signal}, issued_by)

    @staticmethod
    def request_exec(host_id, cmd, timeout, issued_by):
        cmd = (cmd or "").strip()
        if not cmd:
            raise ValidationError("command is empty")
        timeout = _clamp(_coerce_int(timeout, "timeout"), MIN_EXEC_TIMEOUT, MAX_EXEC_TIMEOUT)
        return db.queue_command(host_id, "exec",
                                {"cmd": cmd, "timeout": timeout}, issued_by)

    @staticmethod
    def authorize_result(cmd_id, host):
        """Return the command if it exists and belongs to this host, otherwise
        raise so the route can answer with the right HTTP status."""
        cmd = db.get_command(cmd_id)
        if not cmd:
            raise LookupError("command not found")
        if cmd["host_id"] != host["id"]:
            raise PermissionError("command does not belong to this host")
        return cmd

    @staticmethod
    def save_result(cmd_id, status, exit_code=None, result=None, error=None):
        db.save_command_result(cmd_id, status=status, exit_code=exit_code,
                               result=result, error=error)

    @staticmethod
    def pending_for_agent(host_id):
        """Hand the agent its pending commands in the compact shape it expects,
        marking them as executing so they are not handed out twice."""
        pending = db.get_pending_commands(host_id, mark_executing=True)
        return [{"id": c["id"], "type": c["type"], "payload": c["payload"]} for c in pending]

    @staticmethod
    def process_view(host_id, query=""):
        """Latest process list for a host with an optional case-insensitive
        filter applied across pid, name, user and cmdline."""
        db.cleanup_stuck_commands(stale_minutes=5)
        latest = db.get_latest_process_list(host_id)
        processes, last_refresh = [], None
        if latest and latest["result"]:
            processes = latest["result"].get("processes", [])
            last_refresh = latest["executed_at"]

        query = (query or "").strip().lower()
        if query:
            processes = [
                p for p in processes
                if query in str(p.get("pid"))
                or query in (p.get("name") or "").lower()
                or query in (p.get("user") or "").lower()
                or query in (p.get("cmdline") or "").lower()
            ]
        return processes, last_refresh

    @staticmethod
    def history(host_id, limit=15):
        return db.list_commands(host_id, limit=limit)
