import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

MAIN_PATH = "../data/MachineLearningCVE"

dataset_ddos = pd.read_csv(f"{MAIN_PATH}/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")
dataset_portscan = pd.read_csv(f"{MAIN_PATH}/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv")

dataset_ddos = dataset_ddos.replace([float("inf"), -float("inf")], pd.NA)
dataset_portscan = dataset_portscan.replace([float("inf"), -float("inf")], pd.NA)

dataset_ddos = dataset_ddos.dropna()
dataset_portscan = dataset_portscan.dropna()

dataset_ddos.columns = dataset_ddos.columns.str.strip()
dataset_portscan.columns = dataset_portscan.columns.str.strip()

frames = [dataset_portscan, dataset_ddos]
dataset = pd.concat(frames)
features = ["Flow Duration", "Total Fwd Packets", "Total Backward Packets", 
            "Total Length of Fwd Packets", "Total Length of Bwd Packets"]
X = dataset[features]
y = dataset["Label"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

pipeline = Pipeline([
    ("model", RandomForestClassifier(n_estimators=200, max_depth=20, verbose=0, n_jobs=-1))
])

pipeline.fit(X_train, y_train)
y_pred = pipeline.predict(X_test)

print(classification_report(y_test, y_pred))
print(X_train.columns)
joblib.dump(pipeline, "pipeline.pkl")
