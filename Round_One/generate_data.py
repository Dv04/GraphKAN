import pandas as pd
import numpy as np
from datetime import datetime, timedelta


def generate_complex_data(num_rows=100000):
    np.random.seed(42)
    start_date = datetime(2024, 1, 1)

    device_ids = [f"Device_{i}" for i in range(1, 41)]
    protocols = ["HTTP", "HTTPS", "MQTT", "TCP", "UDP", "ICMP", "ARP", "DNS"]
    attack_types = ["Benign", "DDoS", "DoS", "Recon", "Spoofing", "MQTT"]
    tcp_flags = ["SYN", "ACK", "FIN", "RST", "PSH", "URG"]

    num_attack_types = len(attack_types)
    rows_per_attack = num_rows // num_attack_types
    remaining_rows = num_rows % num_attack_types

    attack_repeats = [rows_per_attack] * num_attack_types
    for i in range(remaining_rows):
        attack_repeats[i] += 1

    data = {
        "Device_ID": np.random.choice(device_ids, num_rows),
        "Timestamp": [start_date + timedelta(seconds=i) for i in range(num_rows)],
        "Packet_Size": np.random.randint(20, 1500, num_rows),
        "Protocol": np.random.choice(protocols, num_rows),
        "Source_IP": np.random.choice(
            ["192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4"], num_rows
        ),
        "Destination_IP": np.random.choice(
            ["192.168.1.5", "192.168.1.6", "192.168.1.7", "192.168.1.8"], num_rows
        ),
        "Source_Port": np.random.randint(1024, 65535, num_rows),
        "Destination_Port": np.random.randint(1024, 65535, num_rows),
        "TCP_Flags": np.random.choice(tcp_flags, num_rows),
        "Attack_Type": np.repeat(attack_types, attack_repeats),
        "Header_Length": np.random.randint(0, 100000, num_rows),
        "Duration": np.random.randint(1, 256, num_rows),
        "Rate": np.random.randint(1, 1000000, num_rows),
        "Srate": np.random.randint(1, 1000000, num_rows),
        "fin_flag_number": np.random.randint(0, 2, num_rows),
        "syn_flag_number": np.random.randint(0, 2, num_rows),
        "rst_flag_number": np.random.randint(0, 2, num_rows),
        "psh_flag_number": np.random.randint(0, 2, num_rows),
        "ack_flag_number": np.random.randint(0, 2, num_rows),
        "ece_flag_number": np.random.randint(0, 2, num_rows),
        "cwr_flag_number": np.random.randint(0, 2, num_rows),
        "ack_count": np.random.randint(0, 12, num_rows),
        "syn_count": np.random.randint(0, 11, num_rows),
        "fin_count": np.random.randint(0, 152, num_rows),
        "rst_count": np.random.randint(0, 9577, num_rows),
    }

    df = pd.DataFrame(data)
    df.to_csv("complex_synthetic_data.csv", index=False)
    print("Complex data generation complete. 'complex_synthetic_data.csv' created.")


if __name__ == "__main__":
    generate_complex_data()
