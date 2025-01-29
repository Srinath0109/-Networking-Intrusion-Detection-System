import joblib
import numpy as np
from logger import log_intrusion

# Load pre-trained ML model
model = joblib.load("intrusion_model.pkl")

def detect_intrusion(packet_data):
    """Predicts if the packet is malicious using the ML model."""
    if packet_data:
        features = np.array([[
            packet_data["protocol"],
            packet_data["flags"],
            packet_data["payload_size"]
        ]])
        
        prediction = model.predict(features)
        
        if prediction[0] == 1:
            log_intrusion(packet_data)
            return True
    return False
