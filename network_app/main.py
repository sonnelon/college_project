import pandas as pd
import joblib
from scapy.all import sniff, IP, TCP, UDP
import time

MODEL_PATH = "pipeline.pkl"
FEATURES = ["Flow Duration", "Total Fwd Packets", "Total Backward Packets",
            "Total Length of Fwd Packets", "Total Length of Bwd Packets"]

try:
    pipeline = joblib.load(MODEL_PATH)
    print("Модель успешно загружена. Ожидание трафика...")
except Exception as e:
    print(f"Ошибка загрузки модели: {e}")
    exit()

flows = {}

def process_packet(packet):
    if IP not in packet:
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    proto = packet[IP].proto
    
    sport = packet.sport if (TCP in packet or UDP in packet) else 0
    dport = packet.dport if (TCP in packet or UDP in packet) else 0

    fwd_key = (src_ip, dst_ip, sport, dport, proto)
    bwd_key = (dst_ip, src_ip, dport, sport, proto)
    
    current_time = time.time()

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
            'bwd_len': 0,
            'already_detected': False
        }
        direction = 'fwd'

    packet_len = packet[IP].len if packet[IP].len is not None else 0

    flows[key]['last_packet_time'] = current_time
    if direction == 'fwd':
        flows[key]['fwd_packets'] += 1
        flows[key]['fwd_len'] += packet_len
    else:
        flows[key]['bwd_packets'] += 1
        flows[key]['bwd_len'] += packet_len

    total_packets = flows[key]['fwd_packets'] + flows[key]['bwd_packets']
    
    if total_packets >= 3 and not flows[key]['already_detected']:
        analyze_flow(key)

def analyze_flow(key):
    data = flows[key]
    
    duration = int((data['last_packet_time'] - data['start_time']) * 1000000)
    
    input_data = pd.DataFrame([[
        duration,
        data['fwd_packets'],
        data['bwd_packets'],
        data['fwd_len'],
        data['bwd_len']
    ]], columns=FEATURES)

    prediction = pipeline.predict(input_data)[0]
    
    if str(prediction).lower() != "benign":
        print(f"[!] ОБНАРУЖЕНА АТАКА: {prediction} | Поток: {key[0]}:{key[2]} -> {key[1]}:{key[4]}")
        print(f"    Метрики отправленные в модель: {input_data.values.tolist()}")
        data['already_detected'] = True 
    else:
        # print(f"[i] Обычный трафик: {key[0]} -> {key[1]} ({duration} us)")
        pass

last_cleanup = time.time()
def cleanup_flows():
    global last_cleanup
    now = time.time()
    if now - last_cleanup < 10:
        return
    
    to_delete = [k for k, v in flows.items() if now - v['last_packet_time'] > 7.0]
    for k in to_delete:
        del flows[k]
    last_cleanup = now

def packet_callback(packet):
    process_packet(packet)
    cleanup_flows()

try:
    print("Сниффер запущен. Провожу мониторинг...")
    sniff(filter="ip", prn=packet_callback, store=0)
except KeyboardInterrupt:
    print("\nМониторинг остановлен.")
