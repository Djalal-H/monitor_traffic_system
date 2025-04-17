# sniffer.py
import subprocess
import csv


def capture_packets(interface="wlo1", output_file="captured_packets.csv"):
    fields = [
        'frame.len', 'frame.time_delta', 'frame.time_delta_displayed', 'frame.time_epoch',
        'frame.time_relative', 'radiotap.length', 'radiotap.timestamp.ts', 'wlan.duration',
        'wlan.fc.frag', 'wlan.fc.order', 'wlan.fc.moredata', 'wlan.fc.protected',
        'wlan.fc.pwrmgt', 'wlan.fc.type', 'wlan.fc.retry', 'wlan.fc.subtype',
        'wlan_radio.duration', 'wlan.seq', 'wlan_radio.data_rate', 'wlan_radio.signal_dbm',
        'wlan_radio.phy', 'wlan.sa', 'wlan.da', 'wlan.bssid',
        'frame.interface_name',
    ]

    cmd = [
        "tshark", "-i", interface, "-I", "-Y", "wlan", "-T", "fields"
    ]

    for field in fields:
        cmd += ["-e", field]

    process = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    print("Starting packet capture...")
    try:
        with open(output_file, mode="w", newline="") as file:
            writer = csv.DictWriter(file, fieldnames=fields)
            writer.writeheader()

            for line in iter(process.stdout.readline, ''):
                values = line.strip().split('\t')
                packet_data = dict(zip(fields, values))
                writer.writerow(packet_data)

    except KeyboardInterrupt:
        print("Stopping packet capture.")
        process.terminate()

if __name__ == "__main__":
    capture_packets()