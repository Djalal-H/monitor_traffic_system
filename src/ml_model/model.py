import numpy as np
from dataclasses import dataclass

THREAT_MAPPINGS = {
    # DDoS related threats
    'ddos_attack': 'ddos',
    'syn_flood': 'ddos',
    'udp_flood': 'ddos',
    
    # Port scan related threats
    'port_scan': 'port_scan',
    'nmap_scan': 'port_scan',
    'stealth_scan': 'port_scan',
    
    # Malware related threats
    'malware': 'malware',
    'trojan': 'malware',
    'ransomware': 'malware',
    
    # Safe traffic
    'normal': None,
    'benign': None
}


@dataclass
class Prediction:
    is_threat: bool
    threat_type: str
    confidence: float

class ThreatDetector:
    def __init__(self, model_path=None):
        # Load your trained ML model here
        self.model = self._load_model(model_path)

    def _load_model(self, model_path):
        # Implement model loading logic
        pass

    def predict(self, features):
        """Predicts if packet is malicious and its type"""
        # Preprocess features
        processed_features = self._preprocess(features)
        
        # Make prediction
        prediction = self.model.predict(processed_features)
        
        # Map the specific threat to general category
        threat_category = THREAT_MAPPINGS.get(prediction.threat_type)
        
        return Prediction(
            is_threat=threat_category is not None,
            threat_type=threat_category,
            confidence=prediction.confidence
        )