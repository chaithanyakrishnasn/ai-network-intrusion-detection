from fastapi import FastAPI
from capture.sniffer import PacketSniffer
import threading
from fastapi import WebSocket, WebSocketDisconnect
import asyncio
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

app = FastAPI()

app.mount("/static", StaticFiles(directory="static"), name="static")

sniffer = PacketSniffer(
    interface=r"\Device\NPF_{A0961EF5-BB21-4ACE-B746-94608AFFC560}"
)


@app.on_event("startup")
async def start_sniffer():

    # Register main event loop
    loop = asyncio.get_running_loop()
    sniffer.alert_manager.set_event_loop(loop)

    thread = threading.Thread(target=sniffer.start, daemon=True)
    thread.start()


@app.get("/alerts")
def get_alerts():
    alerts = sniffer.get_alerts()

    return [
        {
            "type": a.alert_type,
            "src_ip": a.src_ip,
            "dst_ip": a.dst_ip,
            "severity": a.severity,
            "metadata": a.metadata,
            "timestamp": a.timestamp
        }
        for a in alerts
    ]


@app.get("/health")
def health():
    return {"status": "running"}


@app.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    await websocket.accept()
    await sniffer.alert_manager.register(websocket)

    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        await sniffer.alert_manager.unregister(websocket)


@app.get("/stats")
def get_stats():
    return {
        "packet_count": sniffer.packet_count,
        "active_flows": len(sniffer.flow_tracker.flows)
    }


@app.get("/model/status")
def model_status():
    engine = sniffer.anomaly_engine

    return {
        "is_trained": engine.is_trained,
        "training_samples": len(engine.training_data),
        "last_train_time": engine.last_train_time
    }


@app.get("/metrics")
def alert_metrics():
    alerts = sniffer.get_alerts()

    counts = {}
    for a in alerts:
        counts[a.alert_type] = counts.get(a.alert_type, 0) + 1

    return counts


@app.get("/")
def root():
    return FileResponse("static/index.html")
