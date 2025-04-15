from scapy.all import sniff, AsyncSniffer
import asyncio

class PacketSniffer:
    def __init__(self, interface="eth0"):
        self.interface = interface
        self.async_sniffer = AsyncSniffer(iface=self.interface)

    async def capture_packet(self):
        """Captures network packets asynchronously"""
        return await self.async_sniffer.next()

    def process_packet(self, packet):
        """Extracts relevant features from packet"""
        features = {
            'src_ip': packet.src,
            'dst_ip': packet.dst,
            'protocol': packet.proto,
            'length': len(packet),
            'timestamp': packet.time
        }
        return features