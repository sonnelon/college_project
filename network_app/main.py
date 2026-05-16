import pandas as pd
import joblib
from scapy.all import sniff, IP, TCP, UDP
import time

MODEL_PATH = "../model/pipeline.pkl"
FEATURES = ["Flow Duration", "Total Fwd Packets", "Total Backward Packets",
            "Total Length of Fwd Packets", "Total Length of Bwd Packets"]

try:
    pipeline = joblib.load(MODEL_PATH)
    print("Модель загружена. Мониторинг запущен...")
except Exception as e:
    print(f"Ошибка загрузки: {e}")
    exit()

flows = {}
FLOW_TIMEOUT = 5.0 

def process_packet(packet):
    if IP not in packet:
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    proto = packet[IP].proto
    
    sport = packet.sport if (TCP in packet or UDP in packet) else 0
    dport = packet.dport if (TCP in packet or UDP in packet) else 0

    forward_key = (src_ip, dst_ip, sport, dport, proto)
    backward_key = (dst_ip, src_ip, dport, sport, proto)

    current_time = time.time()

    if forward_key in flows:
        flow_key = forward_key
        direction = 'fwd'
    elif backward_key in flows:
        flow_key = backward_key
        direction = 'bwd'
    else:
        flow_key = forward_key
        flows[flow_key] = {
            'start_time': current_time,
            'last_active': current_time,
            'fwd_packets': 0,
            'bwd_packets': 0,
            'fwd_len': 0,
            'bwd_len': 0
        }
        direction = 'fwd'

    packet_len = packet[IP].len if hasattr(packet[IP], 'len') else len(packet)

    flows[flow_key]['last_active'] = current_time
    if direction == 'fwd':
        flows[flow_key]['fwd_packets'] += 1
        flows[flow_key]['fwd_len'] += packet_len
    else:
        flows[flow_key]['bwd_packets'] += 1
        flows[flow_key]['bwd_len'] += packet_len

    if process_packet.packet_count % 20 == 0:
        check_timeouts()
        
    process_packet.packet_count += 1

process_packet.packet_count = 0

def check_timeouts():
    current_time = time.time()
    dead_keys = []
    
    for key, data in flows.items():
        if current_time - data['last_active'] > FLOW_TIMEOUT:
            analyze_flow(key, data)
            dead_keys.append(key)
            
    for key in dead_keys:
        del flows[key]

def analyze_flow(flow_key, data):
    duration = (data['last_active'] - data['start_time']) * 1000000 
    
    if duration == 0 and data['fwd_packets'] + data['bwd_packets'] <= 1:
        return

    input_data = pd.DataFrame([[
        duration,
        data['fwd_packets'],
        data['bwd_packets'],
        data['fwd_len'],
        data['bwd_len']
    ]], columns=FEATURES)

    prediction = pipeline.predict(input_data)[0]
    
    pred_str = str(prediction).lower()
    if pred_str != "benign" and pred_str != "0":
        print(f"[!] АТАКА ДЕТЕКТИРОВАНА: {prediction} | СЛЕД: {flow_key[0]} -> {flow_key[1]}")
    else:
        print(f"[i] Нормальный трафик: {flow_key[0]} -> {flow_key[1]}")

try:
    sniff(filter="ip", prn=process_packet, store=0)
except KeyboardInterrupt:
    print("\nОстановка мониторинга.")
