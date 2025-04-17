import subprocess

def retrieve_ip(mac_address):
    """
    Retrieve the IP address associated with a given MAC address.

    Args:
        mac_address (str): The MAC address to look up.

    Returns:
        str: The associated IP address, or None if not found.
    """
    try:
        # Run the ARP command to get the ARP table
        result = subprocess.run(['arp', '-a'], capture_output=True, text=True, check=True)
        arp_table = result.stdout

        # Search for the MAC address in the ARP table
        for line in arp_table.splitlines():
            if mac_address.lower() in line.lower():
                # Extract the IP address from the line
                parts = line.split()
                for part in parts:
                    if part.startswith('(') and part.endswith(')'):
                        return part.strip('()')
        return None
    except Exception as e:
        print(f"Error retrieving IP address: {e}")
        return None
    