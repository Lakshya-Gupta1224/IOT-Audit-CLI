"""
simulate_device.py — IoT Device Simulator for Laboratory & Academic Demonstrations

Simulates a dual-interface connected IoT edge node (such as a smart environment sensor
or gateway) with deliberately exposed vulnerabilities for testing and demonstration:

Interfaces simulated:
  1. MQTT Telemetry Node:
     - Connects anonymously to an MQTT broker (or publishes via TCP/UDP).
     - Emits continuous synthetic telemetry (temperature, humidity, sensor status).
     - Demonstrates OWASP I1 (Missing auth) & I2 (Wildcard namespace exposure).

  2. HTTP Embedded Web Management Console:
     - Embedded lightweight HTTP server on port 8080 (or configurable).
     - Exposes unauthenticated diagnostic endpoints (/system/info, /api/device).
     - Provides a demo web login form vulnerable to default vendor credentials (admin/admin).
     - Demonstrates OWASP I1, I3, and I7.

Usage:
  python scripts/simulate_device.py --http-port 8080
  python scripts/simulate_device.py --broker 127.0.0.1 --mqtt-port 1883 --http-port 8080
"""

from __future__ import annotations

import argparse
import http.server
import json
import random
import socketserver
import sys
import threading
import time
from datetime import datetime, timezone

try:
    import paho.mqtt.client as mqtt

    PAHO_AVAILABLE = True
except ImportError:
    PAHO_AVAILABLE = False


# ── Embedded HTTP Management Console ──────────────────────────────────────────


class IoTDeviceHTTPHandler(http.server.BaseHTTPRequestHandler):
    server_version = "Embedded-Linux-Lighttpd/1.4"
    sys_version = ""

    def log_message(self, format, *args):
        # Clean logging
        sys.stderr.write(f"[HTTP] {self.address_string()} - {format % args}\n")

    def do_GET(self):
        if self.path in ("/", "/login", "/login.html"):
            # Web Login Form vulnerable to default admin/admin
            html = """<!DOCTYPE html>
<html>
<head><title>IoT Gateway Console</title></head>
<body>
  <h2>IoT Gateway - System Management</h2>
  <form method="POST" action="/login">
    <p>User: <input type="text" name="username" value="admin"/></p>
    <p>Pass: <input type="password" name="password"/></p>
    <p><input type="submit" value="Login"/></p>
  </form>
</body>
</html>"""
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(html)))
            self.end_headers()
            self.wfile.write(html.encode("utf-8"))

        elif self.path in ("/system/info", "/api/device", "/status"):
            # Unauthenticated diagnostic endpoint (OWASP I3 / CWE-200)
            info = {
                "device_id": "EDGE-GW-8821",
                "model": "SmartSensor-PRO-v2",
                "firmware_version": "1.0.4-rc2",
                "uptime_seconds": int(time.time() - getattr(self.server, "start_time", time.time())),
                "cpu_load": f"{random.uniform(5.0, 25.0):.1f}%",
                "memory_free_kb": 14320,
                "sensors": {
                    "temperature": f"{random.uniform(21.0, 26.5):.2f} C",
                    "humidity": f"{random.uniform(40.0, 60.0):.1f} %",
                },
                "status": "OPERATIONAL",
            }
            body = json.dumps(info, indent=2).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(length).decode("utf-8", errors="replace")

        # Weak default credentials check: admin/admin or admin/<blank>
        is_authenticated = (
            ("username=admin" in post_data and "password=admin" in post_data)
            or ("username=admin" in post_data and "password=&" in post_data)
            or ("user=admin" in post_data and "password=admin" in post_data)
        )

        if is_authenticated:
            # Redirect to management dashboard (OWASP I1 vulnerability trigger)
            self.send_response(302)
            self.send_header("Location", "/dashboard")
            self.send_header("Set-Cookie", "session=logged_in_as_admin_token_xyz")
            self.end_headers()
        else:
            # Re-render form with error message
            html = "<html><body><h3>Invalid credentials!</h3><a href='/login'>Try again</a></body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(html)))
            self.end_headers()
            self.wfile.write(html.encode("utf-8"))


def run_http_server(port: int = 8080):
    handler = IoTDeviceHTTPHandler
    with socketserver.ThreadingTCPServer(("0.0.0.0", port), handler) as httpd:
        httpd.start_time = time.time()
        print(f"[+] HTTP Web Console active on http://0.0.0.0:{port}")
        print(f"    - Login Form: http://127.0.0.1:{port}/login  (default: admin / admin)")
        print(f"    - Diagnostic: http://127.0.0.1:{port}/system/info")
        httpd.serve_forever()


# ── Simulated MQTT Telemetry Publisher ────────────────────────────────────────


def run_mqtt_telemetry(broker: str, port: int = 1883, interval: float = 2.0):
    if not PAHO_AVAILABLE:
        print("[!] paho-mqtt not available in current environment; MQTT publisher skipped.")
        return

    print(f"[*] Connecting anonymously to MQTT Broker at {broker}:{port}...")
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="SimulatedEdgeSensor-Node1")

    try:
        client.connect(broker, port, keepalive=30)
        client.loop_start()
        print("[+] MQTT Telemetry node active! Emitting telemetry stream...")

        while True:
            temp = round(random.uniform(20.5, 28.0), 2)
            humidity = round(random.uniform(45.0, 65.0), 1)
            payload = {
                "device_id": "sensor_node_01",
                "temperature_c": temp,
                "humidity_pct": humidity,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            client.publish("sensors/telemetry/node1", json.dumps(payload))
            client.publish("sensors/status", "ACTIVE")
            time.sleep(interval)
    except Exception as e:
        print(f"[!] MQTT Telemetry publisher paused/stopped ({e}).")
        print(f"    (Ensure Mosquitto broker is running: run .\\scripts\\setup_demo_broker.ps1)")


# ── Entrypoint ────────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(description="Simulated Vulnerable IoT Edge Device")
    parser.add_argument("--http-port", type=int, default=8080, help="Web Console Port (default: 8080)")
    parser.add_argument("--broker", type=str, default="127.0.0.1", help="MQTT Broker host (default: 127.0.0.1)")
    parser.add_argument("--mqtt-port", type=int, default=1883, help="MQTT Broker port (default: 1883)")
    parser.add_argument("--interval", type=float, default=2.0, help="Telemetry publish interval (default: 2.0s)")
    parser.add_argument("--no-mqtt", action="store_true", help="Run HTTP server only")
    args = parser.parse_args()

    print("=" * 65)
    print("      IoT Device Simulator — Academic Research & Demo Sandbox    ")
    print("=" * 65)

    # Start HTTP server thread
    http_thread = threading.Thread(target=run_http_server, args=(args.http_port,), daemon=True)
    http_thread.start()

    # Start MQTT publisher thread
    if not args.no_mqtt:
        mqtt_thread = threading.Thread(
            target=run_mqtt_telemetry,
            args=(args.broker, args.mqtt_port, args.interval),
            daemon=True,
        )
        mqtt_thread.start()

    print("\n[+] Target is ready for scanner demonstration:")
    print(f"    Run: iot-audit audit -t 127.0.0.1 -p 8080,1883 -f table\n")
    print("Press Ctrl+C to terminate simulation.")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Simulation shut down cleanly.")


if __name__ == "__main__":
    main()
