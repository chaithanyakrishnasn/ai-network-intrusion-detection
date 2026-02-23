import threading
import asyncio


class AlertManager:

    def __init__(self, max_alerts=1000):
        self.alerts = []
        self.lock = threading.Lock()
        self.max_alerts = max_alerts
        self.subscribers = set()
        self.loop = None  # main event loop reference

    def set_event_loop(self, loop):
        self.loop = loop

    def add_alert(self, alert):
        with self.lock:
            self.alerts.append(alert)

            if len(self.alerts) > self.max_alerts:
                self.alerts.pop(0)

        # Broadcast safely if loop available
        if self.loop:
            self.loop.call_soon_threadsafe(
                asyncio.create_task,
                self.broadcast(alert)
            )

    def get_alerts(self):
        with self.lock:
            return list(self.alerts)

    async def register(self, websocket):
        self.subscribers.add(websocket)

    async def unregister(self, websocket):
        self.subscribers.discard(websocket)

    async def broadcast(self, alert):
        if not self.subscribers:
            return

        message = {
            "type": alert.alert_type,
            "src_ip": alert.src_ip,
            "dst_ip": alert.dst_ip,
            "severity": alert.severity,
            "metadata": alert.metadata,
            "timestamp": alert.timestamp
        }

        dead = []

        for ws in self.subscribers:
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)

        for ws in dead:
            self.subscribers.discard(ws)
