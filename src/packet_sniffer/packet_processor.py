#!/usr/bin/env python3
import pyshark
import csv
import argparse
import os
import time
from datetime import datetime


def capture_packets(interface="wlo1", output_file="output_test_shark.csv", duration=60, display_filter=None, packet_count=None):
    """
    Capture packets from specified interface and extract the requested fields.
    
    Args:
        interface (str): Network interface to capture from (e.g., 'wlan0')
        output_file (str): Path to save the CSV output
        duration (int): Duration of capture in seconds (default: 60)
        display_filter (str): Wireshark display filter (default: None)
        packet_count (int): Number of packets to capture (default: None)
    """
    print(f"Starting packet capture on {interface} for {duration}s or {packet_count if packet_count else 'unlimited'} packets...")
    
    # Define all fields we want to capture
    fields = [
        'frame.len', 'frame.time_delta', 'frame.time_delta_displayed', 
        'frame.time_epoch', 'frame.time_relative', 'radiotap.length', 
        'radiotap.timestamp.ts', 'wlan.duration', 'wlan.fc.frag', 
        'wlan.fc.order', 'wlan.fc.moredata', 'wlan.fc.protected',
        'wlan.fc.pwrmgt', 'wlan.fc.type', 'wlan.fc.retry', 
        'wlan.fc.subtype', 'wlan_radio.duration', 'wlan.seq', 
        'wlan_radio.data_rate', 'wlan_radio.signal_dbm', 'wlan_radio.phy', 
        'wlan.sa', 'wlan.da', 'wlan.bssid', 'frame.interface_name',
        'ip.src', 'ip.dst'
    ]
    
    # Create a live capture
    capture = pyshark.LiveCapture(
        interface=interface,
        display_filter=display_filter
    )
    
    # Set timeout if duration is specified
    if duration:
        capture.set_debug()
        capture.sniff_timeout = duration
    
    # Open CSV file for writing
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        # Write header
        writer.writerow(['timestamp'] + fields)
        
        # Start packet capture
        packet_counter = 0
        start_time = time.time()
        
        try:
            # Apply packet limit if specified
            if packet_count:
                packets = capture.sniff_continuously(packet_count=packet_count)
            else:
                packets = capture.sniff_continuously()
                
            for packet in packets:
                row_data = [datetime.now().isoformat()]
                
                # Extract each field, handling cases where field may not exist
                for field in fields:
                    try:
                        # Split the field name by dots to navigate through packet layers
                        parts = field.split('.')
                        layer_name = parts[0]
                        
                        # Handle special case for frame fields which are in frame_info
                        if layer_name == 'frame' and hasattr(packet, 'frame_info'):
                            value = getattr(packet.frame_info, '_'.join(parts[1:]), '')
                        elif hasattr(packet, layer_name):
                            layer = getattr(packet, layer_name)
                            attr_name = '_'.join(parts[1:])
                            value = getattr(layer, attr_name, '')
                        else:
                            value = ''
                    except (AttributeError, IndexError):
                        value = ''
                    
                    row_data.append(value)
                
                writer.writerow(row_data)
                packet_counter += 1
                
                # Check if we've captured enough packets
                if packet_count and packet_counter >= packet_count:
                    break
                
                # Check if we've captured for long enough
                if duration and (time.time() - start_time) >= duration:
                    break
                    
                # Flush to disk every 10 packets
                if packet_counter % 10 == 0:
                    csvfile.flush()
                    print(f"Captured {packet_counter} packets...")
                
        except KeyboardInterrupt:
            print("\nCapture stopped by user.")
        
    print(f"Capture complete! {packet_counter} packets captured and saved to {output_file}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Capture network traffic and save specified fields to CSV')
    
    parser.add_argument('-i', '--interface', required=True, 
                        help='Network interface to capture from (e.g., wlan0)')
    
    parser.add_argument('-o', '--output', default=f'capture_{int(time.time())}.csv',
                        help='Output CSV file path (default: capture_<timestamp>.csv)')
    
    parser.add_argument('-d', '--duration', type=int, default=60,
                        help='Duration of capture in seconds (default: 60)')
    
    parser.add_argument('-f', '--filter', default=None,
                        help='Wireshark display filter')
    
    parser.add_argument('-c', '--count', type=int, default=None,
                        help='Number of packets to capture')
    
    parser.add_argument('--monitor-mode', action='store_true',
                        help='Enable monitor mode on the interface before capture')
    
    args = parser.parse_args()
    
    # Enable monitor mode if requested
    if args.monitor_mode:
        print(f"Enabling monitor mode on {args.interface}...")
        os.system(f"sudo ip link set {args.interface} down")
        os.system(f"sudo iw {args.interface} set monitor control")
        os.system(f"sudo ip link set {args.interface} up")
        print(f"Monitor mode enabled on {args.interface}")
    
    # Start capture
    capture_packets(
        interface=args.interface,
        output_file=args.output,
        duration=args.duration,
        display_filter=args.filter,
        packet_count=args.count
    )
    
    # Disable monitor mode if it was enabled
    if args.monitor_mode:
        print(f"Disabling monitor mode on {args.interface}...")
        os.system(f"sudo ip link set {args.interface} down")
        os.system(f"sudo iw {args.interface} set type managed")
        os.system(f"sudo ip link set {args.interface} up")
        print(f"Monitor mode disabled on {args.interface}")