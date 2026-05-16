import pandas as pd
import joblib
from scapy.all import sniff, IP, TCP, UDP
import time

MODEL_PATH = "pipeline.pkl"
FEATURES = ["Flow Duration", "Total Fwd Packets", "Total Backward Packets",
            "Total Length of Fwd Packets", "Total Length of Bwd Packets"]

try:
    pipeline = joblib.load(MODEL_PATH)
except Exception:
    exit()

flows = {}
victim_flows = {}
ANALYSIS_INTERVAL = 1.0

def process_packet(packet):
    if IP not in packet:
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    proto = packet[IP].proto
    
    sport = packet.sport if (TCP in packet or UDP in packet) else 0
    dport = packet.dport if (TCP in packet or UDP in packet) else 0

    current_time = time.time()

    victim_key = (dst_ip, dport, proto)
    if victim_key not in victim_flows:
        victim_flows[victim_key] = {
            'start_time': current_time,
            'last_active': current_time,
            'fwd_packets': 0,
            'bwd_packets': 0,
            'fwd_len': 0,
            'bwd_len': 0
        }
    
    payload_len = 0
    if TCP in packet:
        payload_len = len(packet[TCP].payload)
    elif UDP in packet:
        payload_len = len(packet[UDP].payload)

    victim_flows[victim_key]['last_active'] = current_time
    victim_flows[victim_key]['fwd_packets'] += 1
    victim_flows[victim_key]['fwd_len'] += payload_len

    if (current_time - victim_flows[victim_key]['start_time']) >= ANALYSIS_INTERVAL:
        v_data = victim_flows[victim_key]
        v_duration = max(int((v_data['last_active'] - v_data['start_time']) * 1000000), 15)
        if v_data['fwd_packets'] > 50:
            input_data = pd.DataFrame([[v_duration, v_data['fwd_packets'], 0, v_data['fwd_len'], 0]], columns=FEATURES)
            prediction = pipeline.predict(input_data)[0]
            if str(prediction).lower() != "benign" and str(prediction) != "0":
                print(f"[!] DETECTED: {prediction} ON {victim_key[0]}:{victim_key[1]}")
        del victim_flows[victim_key]

    fwd_key = (src_ip, dst_ip, sport, dport, proto)
    bwd_key = (dst_ip, src_ip, dport, sport, proto)

    if fwd_key in flows:
        key = fwd_key
        direction = 'fwd'
    elif bwd_key in flows:
        key = bwd_key
        direction = 'bwd'
    else:
        key = fwd_key
        flows[key] = {
            'start_time': current_time,
            'last_packet_time': current_time,
            'fwd_packets': 0,
            'bwd_packets': 0,
            'fwd_len': 0,
            'bwd_len': 0
        }
        direction = 'fwd'

    flows[key]['last_packet_time'] = current_time
    if direction == 'fwd':
        flows[key]['fwd_packets'] += 1
        flows[key]['fwd_len'] += payload_len
    else:
        flows[key]['bwd_packets'] += 1
        flows[key]['bwd_len'] += payload_len

    total_packets = flows[key]['fwd_packets'] + flows[key]['bwd_packets']
    if total_packets >= 2:
        data = flows[key]
        duration = max(int((data['last_packet_time'] - data['start_time']) * 1000000), 15)
        input_data = pd.DataFrame([[duration, data['fwd_packets'], data['bwd_packets'], data['fwd_len'], data['bwd_len']]], columns=FEATURES)
        prediction = pipeline.predict(input_data)[0]
        if str(prediction).lower() != "benign" and str(prediction) != "0":
            print(f"[!] DETECTED: {prediction} | {key[0]} -> {key[1]}")
        del flows[key]

last_cleanup = time.time()
def cleanup():
    global last_cleanup
    now = time.time()
    if now - last_cleanup < 5:
        return
    for k in [k for k, v in flows.items() if now - v['last_packet_time'] > 5.0]:
        del flows[k]
    for k in [k for k, v in victim_flows.items() if now - v['last_active'] > 5.0]:
        del victim_flows[k]
    last_cleanup = now

def callback(packet):
    process_packet(packet)
    cleanup()

try:
    sniff(filter="ip", prn=callback, store=0)
except KeyboardInterrupt:
    exit()
