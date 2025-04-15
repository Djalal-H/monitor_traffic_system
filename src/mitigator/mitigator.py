from enum import Enum
import asyncio
from .actions import BlockAction, RateLimitAction, RedirectAction
import logging

class MitigationAction(Enum):
    BLOCK = "BLOCK"
    RATE_LIMIT = "RATE_LIMIT"
    REDIRECT = "REDIRECT"
    LOG = "LOG"
    PASS = "PASS"

class Mitigator:
    def __init__(self):
        self.action_map = {
            "ddos": self._handle_ddos,
            "port_scan": self._handle_port_scan,
            "malware": self._handle_malware
        }

    async def handle_threat(self, threat_type, packet):
        """Handles different types of threats"""
        handler = self.action_map.get(threat_type)
        return await handler(packet)

    async def _handle_ddos(self, packet):
        print("Mitigating DDoS attack...")
        

        print("DDoS mitigation complete.")
        return MitigationAction.RATE_LIMIT

    async def _handle_port_scan(self, packet):
        print("Mitigating port scan...")
        
        

        print("Port scan mitigation complete.")
        return MitigationAction.BLOCK

    async def _handle_malware(self, packet):
        print("Mitigating malware...")
       

        print("Malware mitigation complete.")
        return MitigationAction.BLOCK

    def reset_mitigations(self):
        """Clears all mitigation rules (for cleanup)"""
        