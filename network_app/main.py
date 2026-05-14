import pandas as pd
import joblib
from scapy.all import sniff, IP
import time
from collections import defaultdict

MODEL_PATH = "../model/pipeline.pkl"
FEATURES = ["Flow Duration", "Total Fwd Packets", "Total Backward Packets",
            "Total Length of Fwd Packets", "Total Length of Bwd Packets"]

try:
    pipeline = joblib.load(MODEL_PATH)
    print("Модель загружена. Начинаю мониторинг трафика...")
except Exception as e:
    print(f"Ошибка загрузки модели: {e}")
    exit()

flows = defaultdict(lambda: {
    'start_time': time.time(),
    'fwd_packets': 0,
    'bwd_packets': 0,
    'fwd_len': 0,
    'bwd_len': 0
})

def process_packet(packet):
    if IP not in packet:
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    proto = packet[IP].proto
    
    sport = packet.sport if hasattr(packet, 'sport') else 0
    dport = packet.dport if hasattr(packet, 'dport') else 0

    flow_key = tuple(sorted([src_ip, dst_ip])) + tuple(sorted([sport, dport])) + (proto,)
    
    current_flow = flows[flow_key]
    
    if src_ip == flow_key[0]:
        current_flow['fwd_packets'] += 1
        current_flow['fwd_len'] += len(packet)
    else:
        current_flow['bwd_packets'] += 1
        current_flow['bwd_len'] += len(packet)

    if (current_flow['fwd_packets'] + current_flow['bwd_packets']) >= 5:
        analyze_flow(flow_key)

def analyze_flow(flow_key):
    data = flows[flow_key]
    duration = (time.time() - data['start_time']) * 1000000 

    input_data = pd.DataFrame([[
        duration,
        data['fwd_packets'],
        data['bwd_packets'],
        data['fwd_len'],
        data['bwd_len']
    ]], columns=FEATURES)

    prediction = pipeline.predict(input_data)[0]
    
    print(f"normal: {prediction} from {flow_key[0]} to {flow_key[1]}")
    if prediction.lower() != "benign":
        print(f"attack: {prediction} detected from {flow_key[0]} to {flow_key[1]}")
    
    del flows[flow_key]

try:
    sniff(filter="ip", prn=process_packet, store=0)
except KeyboardInterrupt:
    print("\nОстановка мониторинга.")
