import os
import secrets
from functools import wraps

from flask import (Flask, request, jsonify, render_template, redirect,
                   url_for, session, flash, abort)

import database as db
import alerts as alert_engine
from services import (HostService, MetricsService, ThresholdService,
                      AlertService, CommandService, ValidationError)


app = Flask(__name__)
app.secret_key = os.environ.get("MONITOR_SECRET", secrets.token_hex(32))




def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login", next=request.path))
        return fn(*args, **kwargs)
    return wrapper


def get_api_key():
    """Read the API key from a header or the JSON body."""
    key = request.headers.get("X-API-Key")
    if not key and request.is_json:
        key = (request.get_json(silent=True) or {}).get("api_key")
    return key


def authenticated_host():
    """Resolve the host that owns the request's API key, or return an error
    tuple suitable for `return`ing directly from a route."""
    key = get_api_key()
    if not key:
        return None, (jsonify({"error": "missing api key"}), 401)
    host = db.get_host_by_api_key(key)
    if not host:
        return None, (jsonify({"error": "invalid api key"}), 401)
    return host, None


def format_uptime(seconds):
    seconds = int(seconds or 0)
    d, rem = divmod(seconds, 86400)
    h, rem = divmod(rem, 3600)
    m, _   = divmod(rem, 60)
    if d:  return f"{d}d {h}h {m}min"
    if h:  return f"{h}h {m}min"
    return f"{m}min"


app.jinja_env.filters["uptime"] = format_uptime




@app.route("/api/register", methods=["POST"])
def api_register():
    """First call from an agent. Sends { 'hostname', 'description' } and
    receives an API key used for subsequent authentication."""
    data = request.get_json(silent=True) or {}
    try:
        host = HostService.register(data.get("hostname", ""), data.get("description", ""))
    except ValidationError as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({
        "host_id": host["id"],
        "hostname": host["hostname"],
        "api_key": host["api_key"],
        "polling_interval": host["polling_interval"],
    }), 201


@app.route("/api/metrics", methods=["POST"])
def api_metrics():
    """Agent submits metrics (auth via X-API-Key). The response carries the
    current polling interval and any commands waiting for the agent."""
    host, err = authenticated_host()
    if err:
        return err
    if not host["active"]:
        return jsonify({"error": "host is disabled"}), 403

    try:
        MetricsService.ingest(host, request.get_json(silent=True) or {})
    except ValidationError as e:
        return jsonify({"error": str(e)}), 400

    return jsonify({
        "status": "ok",
        "polling_interval": host["polling_interval"],
        "active": bool(host["active"]),
        "commands": CommandService.pending_for_agent(host["id"]),
    })


@app.route("/api/commands/<int:cmd_id>/result", methods=["POST"])
def api_command_result(cmd_id):
    """Agent submits the result of an executed command."""
    host, err = authenticated_host()
    if err:
        return err

    try:
        CommandService.authorize_result(cmd_id, host)
    except LookupError:
        return jsonify({"error": "command not found"}), 404
    except PermissionError:
        return jsonify({"error": "command does not belong to this host"}), 403

    data = request.get_json(silent=True) or {}
    CommandService.save_result(
        cmd_id,
        status=data.get("status", "done"),
        exit_code=data.get("exit_code"),
        result=data.get("result"),
        error=data.get("error"),
    )
    return jsonify({"status": "ok"})


@app.route("/api/hosts", methods=["GET"])
@login_required
def api_list_hosts():
    return jsonify(HostService.list_with_status())


@app.route("/api/hosts/<int:host_id>/metrics", methods=["GET"])
@login_required
def api_host_metrics(host_id):
    """Query params: range = 1h|6h|24h|7d (default 1h), limit = int (default 500)."""
    if not HostService.get(host_id):
        abort(404)
    return jsonify(MetricsService.history(
        host_id,
        range_str=request.args.get("range", "1h"),
        limit=request.args.get("limit", 500),
    ))


@app.route("/api/alerts", methods=["GET"])
@login_required
def api_alerts():
    return jsonify(AlertService.list(
        host_id=request.args.get("host_id", type=int),
        only_unresolved=request.args.get("only_unresolved", "false").lower() == "true",
    ))




@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = db.authenticate(request.form.get("username", ""),
                               request.form.get("password", ""))
        if user:
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect(request.args.get("next") or url_for("dashboard"))
        flash("Invalid username or password.", "error")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))



@app.route("/")
@login_required
def dashboard():
    return render_template("dashboard.html",
                           hosts=HostService.list_with_status(),
                           alerts=AlertService.list(only_unresolved=True, limit=10))


@app.route("/hosts/<int:host_id>")
@login_required
def host_detail(host_id):
    host = HostService.get(host_id)
    if not host:
        abort(404)
    return render_template("host_detail.html", host=host,
                           range=request.args.get("range", "1h"))


@app.route("/hosts/<int:host_id>/processes", methods=["GET", "POST"])
@login_required
def host_processes(host_id):
    """Processes: refresh the list, kill by PID, run an arbitrary shell command."""
    host = HostService.get(host_id)
    if not host:
        abort(404)

    if request.method == "POST":
        action = request.form.get("action")
        username = session.get("username", "unknown")
        try:
            if action == "refresh":
                queued = CommandService.request_process_list(host_id, username)
                flash("Process list requested. It will appear after the agent's next poll."
                      if queued else "A refresh is already pending.", "info")
            elif action == "kill":
                CommandService.request_kill(host_id, request.form.get("pid"),
                                            request.form.get("signal", "TERM"), username)
                flash(f"Requested kill of PID={request.form.get('pid')} "
                      f"({request.form.get('signal', 'TERM')}).", "info")
            elif action == "exec":
                CommandService.request_exec(host_id, request.form.get("cmd", ""),
                                            request.form.get("timeout", 30), username)
                flash("Command queued.", "info")
        except ValidationError as e:
            flash(str(e), "error")
        return redirect(url_for("host_processes", host_id=host_id))

    processes, last_refresh = CommandService.process_view(host_id, request.args.get("q", ""))
    return render_template("processes.html",
                           host=host, processes=processes,
                           last_refresh=last_refresh, q=request.args.get("q", "").strip(),
                           history=CommandService.history(host_id, limit=15))


@app.route("/hosts", methods=["GET", "POST"])
@login_required
def hosts_manage():
    """Manual host addition (generates an API key) and editing of settings."""
    if request.method == "POST":
        action = request.form.get("action")
        try:
            if action == "add":
                h = HostService.register(request.form.get("hostname", ""),
                                         request.form.get("description", ""))
                flash(f"Host '{h['hostname']}' added. API key: {h['api_key']}", "success")
            elif action == "update":
                HostService.update_config(
                    int(request.form["host_id"]),
                    polling_interval=request.form.get("polling_interval", 5),
                    active=1 if request.form.get("active") else 0,
                    description=request.form.get("description", ""),
                )
                flash("Settings saved.", "success")
            elif action == "delete":
                HostService.delete(int(request.form["host_id"]))
                flash("Host deleted.", "success")
        except ValidationError as e:
            flash(str(e), "error")
        return redirect(url_for("hosts_manage"))

    return render_template("hosts.html", hosts=HostService.list_with_status())


@app.route("/alerts")
@login_required
def alerts_page():
    only_unresolved = request.args.get("only_unresolved", "false").lower() == "true"
    return render_template("alerts.html",
                           alerts=AlertService.list(only_unresolved=only_unresolved),
                           only_unresolved=only_unresolved)


@app.route("/alerts/<int:alert_id>/resolve", methods=["POST"])
@login_required
def resolve(alert_id):
    AlertService.resolve(alert_id)
    return redirect(request.referrer or url_for("alerts_page"))


@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    """Global alert thresholds."""
    if request.method == "POST":
        try:
            for metric in ("cpu", "ram", "disk"):
                ThresholdService.save(
                    metric,
                    warning=request.form.get(f"{metric}_warning", 80),
                    critical=request.form.get(f"{metric}_critical", 95),
                    host_id=None,
                )
            flash("Thresholds saved.", "success")
        except ValidationError as e:
            flash(str(e), "error")
        return redirect(url_for("settings"))
    return render_template("settings.html", thresholds=ThresholdService.get(None))



def create_app():
    db.init_db()
    alert_engine.start_background_monitor(interval_s=30)
    return app


if __name__ == "__main__":
    create_app()
    print("=" * 60)
    print(" Linux Remote Monitoring System")
    print("=" * 60)
    print(f" Database: {db.DB_PATH}")
    print(" Default login: admin / admin  (please change after first sign-in)")
    print(" Listening on http://0.0.0.0:5000")
    print("=" * 60)
    app.run(host="0.0.0.0", port=5000, debug=False)
