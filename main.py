from src.packet_sniffer.sniffer import PacketSniffer
from src.ml_model.model import ThreatDetector
from src.mitigator.mitigator import Mitigator
import asyncio

class NetworkMonitor:
    def __init__(self):
        self.sniffer = PacketSniffer()
        self.detector = ThreatDetector()
        self.mitigator = Mitigator()

    async def process_packet(self, packet):
        # Process packet and get features
        packet_features = self.sniffer.process_packet(packet)
        
        # Detect threats
        prediction = self.detector.predict(packet_features)
        
        # If threat detected, mitigate
        if prediction.is_threat:
            action = await self.mitigator.handle_threat(prediction.threat_type, packet)
            return action
        
        return "PASS"

    async def run(self):
        while True:
            packet = await self.sniffer.capture_packet()
            await self.process_packet(packet)

if __name__ == "__main__":
    monitor = NetworkMonitor()
    asyncio.run(monitor.run())