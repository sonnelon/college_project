import pandas as pd
import joblib
from scapy.all import sniff, IP
import time
from collections import defaultdict

MODEL_PATH = "../model/pipeline.pkl"
FEATURES = ["Flow Duration", "Total Fwd Packets", "Total Backward Packets",
            "Total Length of Fwd Packets", "Total Length of Bwd Packets"]

# Загружаем модель
try:
    pipeline = joblib.load(MODEL_PATH)
    # Вытаскиваем только имена признаков, если модель ожидает строго их
    print("Модель загружена. Начинаю мониторинг трафика...")
except Exception as e:
    print(f"Ошибка загрузки модели: {e}")
    exit()

# Хранилище для сессий (Flows)
# Ключ: (IP_src, IP_dst, Port_src, Port_dst, Protocol)
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

    # Формируем ключ потока (учитываем оба направления)
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    proto = packet[IP].proto
    
    # Пытаемся определить порты (если есть TCP/UDP)
    sport = packet.sport if hasattr(packet, 'sport') else 0
    dport = packet.dport if hasattr(packet, 'dport') else 0

    # Идентификатор потока (сортируем IP, чтобы входящий и исходящий трафик попал в один flow)
    flow_key = tuple(sorted([src_ip, dst_ip])) + tuple(sorted([sport, dport])) + (proto,)
    
    current_flow = flows[flow_key]
    
    # Определяем направление (упрощенно: первый отправитель — Forward)
    if src_ip == flow_key[0]:
        current_flow['fwd_packets'] += 1
        current_flow['fwd_len'] += len(packet)
    else:
        current_flow['bwd_packets'] += 1
        current_flow['bwd_len'] += len(packet)

    # Каждые N пакетов или по истечении времени делаем проверку
    # В данном примере: проверяем поток, если в нем накопилось более 5 пакетов
    if (current_flow['fwd_packets'] + current_flow['bwd_packets']) >= 5:
        analyze_flow(flow_key)

def analyze_flow(flow_key):
    data = flows[flow_key]
    duration = (time.time() - data['start_time']) * 1000000  # В микросекундах, как в датасете

    # Подготовка данных для модели
    input_data = pd.DataFrame([[
        duration,
        data['fwd_packets'],
        data['bwd_packets'],
        data['fwd_len'],
        data['bwd_len']
    ]], columns=FEATURES)

    # Предсказание
    prediction = pipeline.predict(input_data)[0]
    
    print(f"normal: {prediction} from {flow_key[0]} to {flow_key[1]}")
    if prediction.lower() != "benign":
        print(f"attack: {prediction} detected from {flow_key[0]} to {flow_key[1]}")
    
    # Очищаем данные потока после анализа, чтобы начать новый цикл накопления
    del flows[flow_key]

# Запуск сниффера
# filter="ip" — перехватываем только IP трафик
# store=0 — не сохранять пакеты в памяти (экономия RAM)
try:
    sniff(filter="ip", prn=process_packet, store=0)
except KeyboardInterrupt:
    print("\nОстановка мониторинга.")
