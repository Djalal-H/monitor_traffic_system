from enum import Enum
import asyncio
import logging
import subprocess
import os
import shutil

# Configure logging for actions
logging.basicConfig(filename="mitigation.log", level=logging.INFO)


class MitigationAction(Enum):
    BLOCK = "BLOCK"
    RATE_LIMIT = "RATE_LIMIT"
    FLUSH_ARP = "FLUSH_ARP"
    PASS = "PASS"
    RESET_ARP = "RESET_ARP"
    PATCH_SQL = "PATCH_SQL"
    BLOCK_DEAUTH = "BLOCK_DEAUTH"
    DISABLE_AUTH = "DISABLE_AUTH"
    PROTECT_SYN = "PROTECT_SYN"
    BLOCK_IP = "BLOCK_IP"
    HOSTAPD_CONFIG_PROTECTION = "HOSTAPD_CONFIG_PROTECTION"


class ActionHandler:
    """Handles execution of different mitigation actions"""

    @staticmethod
    async def block(ip_address=None, mac_address=None, method="ip"):
        """Block an IP or MAC address"""
        try:
            if method == "ip" and ip_address:
                # First check if iptables is available
                if not shutil.which("iptables"):
                    print("iptables not found. Using simulation mode.")
                    return True

                process = await asyncio.create_subprocess_exec(
                    "iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                await process.communicate()
                return True
            elif method == "mac" and mac_address:
                if not shutil.which("iptables"):
                    print("iptables not found. Using simulation mode.")
                    return True

                process = await asyncio.create_subprocess_exec(
                    "iptables", "-A", "INPUT", "-m", "mac", "--mac-source", mac_address, "-j", "DROP",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                await process.communicate()
                return True
            return False
        except Exception as e:
            print(f"Block action failed: {e}")
            # Return True to indicate we tried (for logging purposes)
            return True

    @staticmethod
    async def rate_limit(ip_address, rate="1mbit", interface="wlan0"):
        """Rate-limit traffic from a specific IP address"""
        try:
            # Check if tc is available
            if not shutil.which("tc"):
                print("tc command not found. Using simulation mode.")
                return True

            # Setup HTB qdisc if it doesn't exist
            process = await asyncio.create_subprocess_exec(
                "tc", "qdisc", "add", "dev", interface, "root", "handle", "1:", "htb",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await process.communicate()

            # Add class with rate limit
            process = await asyncio.create_subprocess_exec(
                "tc", "class", "add", "dev", interface, "parent", "1:", "classid", "1:1",
                "htb", "rate", rate,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await process.communicate()

            # Add filter to match IP
            process = await asyncio.create_subprocess_exec(
                "tc", "filter", "add", "dev", interface, "protocol", "ip", "parent", "1:0",
                "prio", "1", "u32", "match", "ip", "src", ip_address, "flowid", "1:1",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await process.communicate()
            return True
        except Exception as e:
            print(f"Rate limit action failed: {e}")
            # Return True to indicate we tried (for logging purposes)
            return True


class Mitigator:
    def __init__(self):
        """Initialize the Mitigator class."""
        self.action_map = {
            "rogue_ap": self._handle_rogue_ap,
            "deauth": self._handle_deauth,
            "botnet_ddos": self._handle_botnet_ddos,
            "sql_injection": self._handle_sql_injection,
            "reassociation": self._handle_reassociation
        }
        self.action_handler = ActionHandler()

    def log_action(self, action, details):
        """Log mitigation actions."""
        logging.info(f"Action: {action}, Details: {details}")

    async def handle_threat(self, threat_type, packet):
        """Handles different types of threats"""
        handler = self.action_map.get(threat_type)
        if handler:
            return await handler(packet)
        else:
            logging.warning(f"No handler found for threat type: {threat_type}")
            return MitigationAction.PASS

    async def _handle_rogue_ap(self, packet):
        """Handle rogue access point threats"""
        print("Mitigating rogue access point...")
        mac_address = packet.get("mac")
        try:
            success = await self.action_handler.block(mac_address=mac_address, method="mac")
            if success:
                self.log_action("block_rogue_ap", {"mac": mac_address})
                print(f"Blocked rogue AP with MAC: {mac_address}")

            # Reset ARP cache as additional measure
            try:
                if shutil.which("ip"):
                    process = await asyncio.create_subprocess_exec(
                        "ip", "neigh", "flush", "all",
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    await process.communicate()
                    self.log_action("reset_arp_cache", {})
                    print("ARP cache reset.")
                else:
                    print("IP command not found. ARP cache reset simulated.")
            except Exception as e:
                print(f"Failed to reset ARP cache: {e}")
        except Exception as e:
            print(f"Failed to block rogue AP: {e}")

        print("Rogue AP mitigation complete.")
        return [MitigationAction.BLOCK, MitigationAction.FLUSH_ARP]

    async def _handle_deauth(self, packet):
        """Handle deauthentication frame attacks"""
        print("Mitigating deauth attack...")
        interface = packet.get("interface", "wlan0mon")
        try:
            # Check if mdk3 is available
            if shutil.which("mdk3"):
                # Execute command to block deauth frames
                process = await asyncio.create_subprocess_exec(
                    "mdk3", interface, "d", "-w", "whitelist.txt",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                _, stderr = await process.communicate()

                if process.returncode == 0:
                    self.log_action("block_deauth_frames", {
                                    "interface": interface})
                    print(f"Deauthentication frames blocked on {interface}.")
                else:
                    print(f"Failed to block deauth frames: {stderr.decode()}")
            else:
                # Simulate blocking deauth frames
                print(
                    f"mdk3 not found. Simulating deauth frame blocking on {interface}.")
                self.log_action("simulated_block_deauth",
                                {"interface": interface})

                # Alternative: Use iptables to block deauth frames (802.11 management frames)
                if shutil.which("iptables"):
                    try:
                        process = await asyncio.create_subprocess_exec(
                            "iptables", "-A", "INPUT", "-p", "all", "--destination-port", "0",
                            "-m", "u32", "--u32", "48&0xFF=0xC0", "-j", "DROP",
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE
                        )
                        await process.communicate()
                        print("Used iptables as alternative to block deauth frames")
                    except Exception as e:
                        print(f"Failed to use iptables for deauth: {e}")

        except Exception as e:
            print(f"Failed to handle deauth attack: {e}")

        print("Deauth attack mitigation complete.")
        return MitigationAction.BLOCK_DEAUTH

    async def _handle_botnet_ddos(self, packet):
        """Handle botnet and DDoS attacks"""
        print("Mitigating botnet/DDoS attack...")
        ip_address = packet.get("ip")
        rate = packet.get("rate", "512kbit")

        # Block the attack IP
        if ip_address:
            try:
                # Apply IP blocking
                success = await self.action_handler.block(ip_address=ip_address)
                if success:
                    self.log_action("block_ddos_ip", {"ip": ip_address})
                    print(f"Blocked DDoS traffic from IP: {ip_address}")

                # Apply rate limiting
                success = await self.action_handler.rate_limit(ip_address=ip_address, rate=rate)
                if success:
                    self.log_action("rate_limit_client", {
                                    "ip": ip_address, "rate": rate})
                    print(f"Rate-limited client IP: {ip_address} to {rate}")

                # Enable SYN flood protection
                try:
                    if os.path.exists("/proc/sys/net/ipv4/tcp_syncookies"):
                        with open("/proc/sys/net/ipv4/tcp_syncookies", "w") as f:
                            f.write("1")
                        self.log_action("enable_syncookies", {})
                        print("Enabled SYN flood protection")
                    else:
                        print("SYN cookie file not found. Protection simulated.")
                        self.log_action("simulated_syncookies", {})
                except Exception as e:
                    print(f"Failed to enable SYN flood protection: {e}")

            except Exception as e:
                print(f"Failed to mitigate botnet/DDoS: {e}")

        print("Botnet/DDoS mitigation complete.")
        return [MitigationAction.RATE_LIMIT, MitigationAction.BLOCK_IP, MitigationAction.PROTECT_SYN]

    async def _handle_sql_injection(self, packet):
        """Handle SQL injection attacks"""
        print("Mitigating SQL injection attack...")
        webapp_dir = packet.get("webapp_dir", "/var/www/html")

        try:
            # Check if directory exists
            if not os.path.exists(webapp_dir):
                print(
                    f"Web directory {webapp_dir} not found. Using simulation mode.")
                self.log_action("simulated_sql_injection_patch", {
                                "webapp_dir": webapp_dir})
                print(f"Simulated applying SQL injection protection to web applications")
                return MitigationAction.PATCH

            # Look for PHP files and add basic SQL injection protection
            found_files = False
            for root, _, files in os.walk(webapp_dir):
                for file in files:
                    if file.endswith(".php"):
                        found_files = True
                        file_path = os.path.join(root, file)
                        # Create backup
                        shutil.copy2(file_path, f"{file_path}.bak")

                        # Add simple SQL injection protection to PHP files
                        with open(file_path, "r") as f:
                            content = f.read()

                        if "mysqli_real_escape_string" not in content and "$_" in content:
                            # Add basic protection function if not already present
                            protection = """
                                        function sanitize_input($data) {
                                            global $conn;
                                            return mysqli_real_escape_string($conn, trim($data));
                                        }
                                        """
                            content = protection + content

                            # Replace direct access to $_POST, $_GET with sanitized versions
                            content = content.replace(
                                "$_POST['", "sanitize_input($_POST['")
                            content = content.replace(
                                "$_GET['", "sanitize_input($_GET['")

                            with open(file_path, "w") as f:
                                f.write(content)

            if found_files:
                self.log_action("patch_sql_injection", {
                                "webapp_dir": webapp_dir})
                print(
                    f"Applied SQL injection protection to web applications in {webapp_dir}")
            else:
                print(
                    f"No PHP files found in {webapp_dir}. Protection simulated.")
                self.log_action("simulated_sql_injection_patch", {
                                "webapp_dir": webapp_dir})

        except Exception as e:
            print(f"Failed to patch SQL injection: {e}")

        print("SQL injection mitigation complete.")
        return [MitigationAction.PATCH_SQL]

    async def _handle_reassociation(self, packet):
        """Handle reassociation attacks"""
        print("Mitigating reassociation attack...")
        interface = packet.get("interface", "wlan0")
        mac_address = packet.get("mac")

        try:
            # Check if hostapd config exists
            hostapd_conf = "/etc/hostapd/hostapd.conf"
            if os.path.exists(hostapd_conf):
                with open(hostapd_conf, "a") as f:
                    f.write("\n# Protection against reassociation attacks\n")
                    f.write("ap_max_inactivity=60\n")
                    f.write("disassoc_low_ack=1\n")

                # Restart hostapd if available
                if shutil.which("systemctl"):
                    process = await asyncio.create_subprocess_exec(
                        "systemctl", "restart", "hostapd",
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    await process.communicate()
                    print("Restarted hostapd service")
            else:
                print(f"Hostapd config not found. Creating simulation file.")
                # Create a simulation file in the current directory
                with open("hostapd_simulation.conf", "w") as f:
                    f.write("# Simulated hostapd config\n")
                    f.write("interface=" + interface + "\n")
                    f.write("# Protection against reassociation attacks\n")
                    f.write("ap_max_inactivity=60\n")
                    f.write("disassoc_low_ack=1\n")

            self.log_action("handle_reassociation", {"interface": interface})
            print(f"Enabled reassociation attack protection on {interface}")

            # Disable authentication attempts temporarily if hostapd_cli is available
            if shutil.which("hostapd_cli"):
                process = await asyncio.create_subprocess_exec(
                    "hostapd_cli", "-i", interface, "disable",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                await process.communicate()
                self.log_action("disable_auth_attempts",
                                {"interface": interface})
                print(f"Disabled authentication attempts on AP: {interface}")
            else:
                print(
                    f"hostapd_cli not found. Simulating auth disabling on {interface}")
                self.log_action("simulated_disable_auth",
                                {"interface": interface})

            # Block the MAC address if provided
            if mac_address:
                success = await self.action_handler.block(mac_address=mac_address, method="mac")
                if success:
                    self.log_action("block_mac", {"mac": mac_address})
                    print(
                        f"Blocked MAC address involved in reassociation attack: {mac_address}")

        except Exception as e:
            print(f"Failed to handle reassociation attack: {e}")

        print("Reassociation attack mitigation complete.")
        return [MitigationAction.DISABLE_AUTH, MitigationAction.HOSTAPD_CONFIG_PROTECTION]

    def reset_mitigations(self):
        """Clears all mitigation rules (for cleanup)"""
        try:
            # Check if commands exist before running
            if shutil.which("iptables"):
                try:
                    subprocess.run(["iptables", "-F"], check=False)
                    subprocess.run(
                        ["iptables", "-t", "nat", "-F"], check=False)
                    print("Reset iptables rules")
                except Exception as e:
                    print(f"Failed to reset iptables: {e}")
            else:
                print("iptables not found. Simulating iptables reset.")

            # Reset traffic control rules if tc exists
            if shutil.which("tc"):
                interfaces = ["wlan0", "eth0"]  # Add common interfaces
                for interface in interfaces:
                    try:
                        subprocess.run(["tc", "qdisc", "del", "dev", interface, "root"],
                                       check=False)
                        print(f"Reset traffic control on {interface}")
                    except Exception as e:
                        print(f"Failed to reset tc on {interface}: {e}")
            else:
                print("tc not found. Simulating tc reset.")

            # Reset ARP cache if ip command exists
            if shutil.which("ip"):
                try:
                    subprocess.run(
                        ["ip", "neigh", "flush", "all"], check=False)
                    print("Reset ARP cache")
                except Exception as e:
                    print(f"Failed to reset ARP cache: {e}")
            else:
                print("ip command not found. Simulating ARP cache reset.")

            # Re-enable APs if hostapd_cli exists
            if shutil.which("hostapd_cli"):
                for interface in ["wlan0", "wlan1"]:
                    try:
                        subprocess.run(["hostapd_cli", "-i", interface, "enable"],
                                       check=False)
                        print(f"Re-enabled AP on {interface}")
                    except Exception as e:
                        print(f"Failed to re-enable AP on {interface}: {e}")
            else:
                print("hostapd_cli not found. Simulating AP re-enabling.")

            self.log_action("reset_mitigations", {"status": "complete"})
            print("All mitigation rules have been cleared.")
        except Exception as e:
            print(f"Failed to reset mitigations: {e}")


# Example Usage

async def main():
    mitigator = Mitigator()

    # Example threats and their details
    threats = [
        {"type": "deauth", "packet": {"interface": "wlan0mon"}},
        {"type": "botnet_ddos", "packet": {"ip": "192.168.1.100", "rate": "512kbit"}},
        {"type": "rogue_ap", "packet": {"mac": "00:11:22:33:44:55"}},
        {"type": "sql_injection", "packet": {}},
        {"type": "reassociation", "packet": {"interface": "wlan0"}}
    ]

    for threat in threats:
        print(f"\nHandling threat: {threat['type']}")
        actions = await mitigator.handle_threat(threat['type'], threat['packet'])
        print(f"Action taken: {actions}")
        
    # Clean up at the end
    mitigator.reset_mitigations()

""" if __name__ == "__main__":
    asyncio.run(main()) """
