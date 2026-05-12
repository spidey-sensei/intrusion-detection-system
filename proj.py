from flask import Flask, render_template, jsonify
import pyshark
import threading
import time
from collections import defaultdict, deque

app = Flask(__name__)
INTERFACE = "en0"
packet_counts = defaultdict(int)

protocol_counts = defaultdict(int)

alerts = []

paused = False

last_alert_time = defaultdict(dict)
packet_timestamps = defaultdict(deque)

INSECURE_PORTS = {
    "21": "FTP",
    "23": "TELNET",
    "69": "TFTP",
    "80": "HTTP"
}

conversation_details = defaultdict(lambda: {
    "count": 0,
    "protocols": defaultdict(int),
    "ports": set(),
    "packet_sizes": [],
    "last_seen": "",
    "payload": ""
})

ip_profiles = defaultdict(lambda: {
    "avg_rate": 0,
    "last_counts": deque(maxlen=10),
    "ports_used": set()
})

def should_alert(ip, alert_type):
    now = time.time()
    cooldown = 5

    if alert_type == "flood":
        cooldown = 2

    if (
        alert_type not in last_alert_time[ip]
        or now - last_alert_time[ip][alert_type] > cooldown
    ):
        last_alert_time[ip][alert_type] = now
        return True

    return False

# Anomaly detection function
def is_anomalous(ip):
    profile = ip_profiles[ip]
    if len(profile["last_counts"]) < 5:
        return False
    counts = list(profile["last_counts"])
    current_rate = counts[-1]
    baseline = (
        sum(counts[:-1])/ (len(counts) - 1)
    )
    return current_rate > baseline * 2

# Behaviour observation and classification
def classify_behavior(port, rate):
    service = INSECURE_PORTS.get(port, "UNKNOWN")
    if rate > 100:
        return f"{service} Flood"
    elif rate > 50:
        return f"Heavy {service} Activity"
    return f"Normal {service} Activity"

# Packet Sniffer
def packet_sniffer():
    global paused
    print(f"[+] Listening on interface: {INTERFACE}")
    capture = pyshark.LiveCapture(interface=INTERFACE)
    for packet in capture.sniff_continuously():
        if paused:
            continue
        try:
            if not hasattr(packet, "ip"):
                continue
            src = packet.ip.src
            dst = packet.ip.dst
            protocol = packet.transport_layer or "OTHER"

            if protocol not in ["TCP", "UDP"]:
                continue

            port = "0"

            if hasattr(packet, "tcp"):
                port = packet.tcp.dstport

            elif hasattr(packet, "udp"):
                port = packet.udp.dstport

            # Port filtering
            if port not in INSECURE_PORTS:
                continue

            print(f"{src} -> {dst} | {protocol} | Port {port}")
            packet_counts[src] += 1
            protocol_counts[protocol] += 1
            now = time.time()
            packet_timestamps[src].append(now)

            while (
                packet_timestamps[src]
                and now - packet_timestamps[src][0] > 10
            ):
                packet_timestamps[src].popleft()
            current_rate = len(packet_timestamps[src])

            # Conversation tracker
            key = f"{src} → {dst}"
            conv = conversation_details[key]
            conv["count"] += 1
            conv["protocols"][protocol] += 1
            conv["ports"].add(port)

            if hasattr(packet, "length"):
                size = int(packet.length)
                conv["packet_sizes"].append(size)

            try:
                if hasattr(packet, "data"):
                    conv["payload"] = str(packet.data)[:200]

            except:
                pass

            conv["last_seen"] = time.strftime("%H:%M:%S")
            profile = ip_profiles[src]
            profile["last_counts"].append(current_rate)
            profile["avg_rate"] = (
                sum(profile["last_counts"])/ len(profile["last_counts"])
            )
            profile["ports_used"].add(port)

            behavior = classify_behavior(
                port,
                current_rate
            )

            # Anomaly detection
            if is_anomalous(src):
                if should_alert(src, "anomaly"):
                    alerts.append({
                        "ip": src,
                        "msg": (
                            f"Sudden Spike from {src} "
                            f"using {INSECURE_PORTS[port]} "
                            f"({current_rate} packets / 10 sec)"
                        ),
                        "time": time.strftime("%H:%M:%S")
                    })

                    print(
                        f"[ALERT] Spike detected "
                        f"from {src}"
                    )

            # Flood alert
            if current_rate > 100:
                if should_alert(src, "flood"):
                    alerts.append({
                        "ip": src,
                        "msg": (
                            f"ACTIVE FLOOD from {src} "
                            f"using {INSECURE_PORTS[port]} "
                            f"({current_rate} packets / 10 sec)"
                        ),
                        "time": time.strftime("%H:%M:%S")
                    })

                    print(
                        f"[FLOOD ACTIVE] "
                        f"{src} | Rate: {current_rate}"
                    )

        except Exception as e:

            print("[ERROR]", e)

            continue

threading.Thread(
    target=packet_sniffer,
    daemon=True
).start()

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/data")
def data():
    top_conversations = sorted(
        conversation_details.items(),
        key=lambda x: x[1]["count"],
        reverse=True
    )[:10]
    formatted_convs = []
    for conv, details in top_conversations:
        avg_size = (
            sum(details["packet_sizes"])/ len(details["packet_sizes"])
            if details["packet_sizes"]
            else 0
        )
        formatted_convs.append({
            "key": conv,
            "count": details["count"],
            "protocols": dict(details["protocols"]),
            "ports": list(details["ports"]),
            "avg_size": round(avg_size, 2),
            "last_seen": details["last_seen"],
            "payload": details["payload"]
        })
    return jsonify({
        "top_talkers": sorted(
            packet_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )[:5],
        "protocols": dict(protocol_counts),
        "conversations": formatted_convs,
        "alerts": alerts[-20:]
    })

@app.route("/pause")
def pause():
    global paused
    paused = True
    return "paused"

@app.route("/resume")
def resume():
    global paused
    paused = False
    return "resumed"

if __name__ == "__main__":

    app.run(
        debug=True,
        host="0.0.0.0",
        port=5000
    )