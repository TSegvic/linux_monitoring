"""
alerts.py
---------
Infrastructure for the alerting subsystem: the background thread that
periodically scans for hosts that have gone offline.

The alerting policy itself (what counts as a warning, a critical, or an offline
host) lives in services.AlertService. This module only owns the threading
concern - it runs that policy on a timer.
"""

import threading
import time

from services import AlertService


def offline_monitor_loop(interval_s: int = 30):
    while True:
        try:
            AlertService.check_offline_hosts()
        except Exception as e:
            print(f"[offline_monitor] error: {e}")
        time.sleep(interval_s)


def start_background_monitor(interval_s: int = 30):
    t = threading.Thread(target=offline_monitor_loop,
                         args=(interval_s,), daemon=True)
    t.start()
    return t
