# import os
# import pyshark
# import numpy as np
# import pandas as pd
# from sklearn.ensemble import RandomForestClassifier, VotingClassifier
# from sklearn.preprocessing import StandardScaler
# from sklearn.metrics import classification_report, accuracy_score
# from joblib import Parallel, delayed

# # Define the main directory path
# main_folder_path = "CICIoMT2024/WiFI_and_MQTT/"


# # Function to assign labels dynamically based on file path or name
# def assign_label(file_path):
#     if "Benign" in file_path:
#         return 0  # Benign
#     elif "ARP_Spoofing" in file_path:
#         return 1  # ARP Spoofing
#     elif "ICMP" in file_path:
#         return 2  # ICMP
#     elif "SYN" in file_path:
#         return 3  # SYN
#     elif "TCP" in file_path:
#         return 4  # TCP
#     elif "UDP" in file_path:
#         return 5  # UDP
#     elif "Connect_Flood" in file_path and "MQTT-DoS" in file_path:
#         return 12  # MQTT-DoS Connect Flood
#     elif "Publish_Flood" in file_path and "MQTT-DDoS" in file_path:
#         return 12  # MQTT-DDoS Publish Flood
#     elif "Malformed_Data" in file_path and "MQTT" in file_path:
#         return 14  # MQTT Malformed Data
#     elif "Ping_Sweep" in file_path:
#         return 16  # Ping Sweep
#     elif "OS_Scan" in file_path:
#         return 15  # OS Scan
#     elif "Port_Scan" in file_path:
#         return 16  # Port Scan
#     elif "VulScan" in file_path:
#         return 17  # VulScan
#     elif "Active" in file_path:
#         return 17  # Active
#     elif "ActiveBroker" in file_path:
#         return 18  # Active Broker
#     elif "Idle" in file_path:
#         return 19  # Idle
#     else:
#         return -1  # Unknown or undefined


# # Generator function to yield packets and labels from PCAP files in chunks
# def packet_generator(folder_path, label_mapping, chunk_size=1000):
#     for root, dirs, files in os.walk(folder_path):
#         for file in files:
#             if file.endswith(".pcap"):
#                 file_path = os.path.join(root, file)
#                 label = assign_label(file_path)
#                 if label != -1:
#                     print(f"Processing file: {file_path} with label: {label}")
#                     cap = pyshark.FileCapture(file_path)
#                     features = []
#                     for packet in cap:
#                         try:
#                             feature_dict = {
#                                 "time": float(packet.sniff_time.timestamp()),
#                                 "length": int(packet.length),
#                             }
#                             features.append((feature_dict, label))
#                             if len(features) == chunk_size:
#                                 yield features
#                                 features = []
#                         except AttributeError:
#                             continue
#                     if features:
#                         yield features
#                     cap.close()


# # Function to preprocess a batch of packets and labels
# def preprocess_batch(batch, scaler=None):
#     X = [list(packet.values()) for packet, _ in batch]
#     y = [label for _, label in batch]
#     X = np.array(X)
#     y = np.array(y)
#     if scaler is not None:
#         X = scaler.transform(X)
#     return X, y


# # Function to train a single RandomForestClassifier on a batch
# def train_single_rf(batch, scaler):
#     X, y = preprocess_batch(batch, scaler)
#     clf = RandomForestClassifier(n_estimators=100, random_state=42)
#     clf.fit(X, y)
#     return clf


# print("Initializing scaler...")
# # Initialize scaler
# scaler = StandardScaler()

# # Initial batch for fitting the scaler
# initial_batch = []
# batch_size = 1000
# packet_gen = packet_generator(main_folder_path, assign_label, chunk_size=batch_size)

# print("Fitting scaler on initial batch...")
# # Fit scaler on initial batch
# for _ in range(batch_size):
#     try:
#         batch = next(packet_gen)
#         initial_batch.extend(batch)
#         if len(initial_batch) >= batch_size:
#             break
#     except StopIteration:
#         break

# X_initial, y_initial = preprocess_batch(initial_batch)
# scaler.fit(X_initial)

# print("Training models incrementally...")
# # Train models incrementally
# models = []
# packet_gen = packet_generator(main_folder_path, assign_label, chunk_size=batch_size)
# for batch in packet_gen:
#     model = train_single_rf(batch, scaler)
#     models.append(model)

# # Create a voting classifier from the trained models
# voting_clf = VotingClassifier(
#     estimators=[(f"rf{i}", model) for i, model in enumerate(models)], voting="soft"
# )

# print("Evaluating model...")
# # Evaluate the model
# X_test, y_test = X_initial, y_initial  # In practice, use a separate test set
# y_pred = voting_clf.fit(X_test, y_test).predict(X_test)

# print("Classification Report:")
# print(classification_report(y_test, y_pred))

# print("Accuracy:", accuracy_score(y_test, y_pred))

# print("Finished!")

import dpkt
import pandas as pd
import os
from collections import defaultdict


# Function to extract features from a single packet
def extract_features(packet, ts, prev_ts, packet_counts):
    features = defaultdict(int)

    try:
        eth = dpkt.ethernet.Ethernet(packet)

        # Check if the packet is an Ethernet frame
        if isinstance(eth, dpkt.ethernet.Ethernet):
            ip = eth.data
            # Ethernet Layer
            features["Header_Length"] = len(eth)

            # IP Layer
            if isinstance(ip, dpkt.ip.IP):
                features["Protocol Type"] = ip.p

                # Transport Layer
                if isinstance(ip.data, dpkt.tcp.TCP):
                    tcp = ip.data
                    features["TCP"] = 1
                    features["fin_flag_number"] += tcp.flags & dpkt.tcp.TH_FIN != 0
                    features["syn_flag_number"] += tcp.flags & dpkt.tcp.TH_SYN != 0
                    features["rst_flag_number"] += tcp.flags & dpkt.tcp.TH_RST != 0
                    features["psh_flag_number"] += tcp.flags & dpkt.tcp.TH_PUSH != 0
                    features["ack_flag_number"] += tcp.flags & dpkt.tcp.TH_ACK != 0
                    features["ece_flag_number"] += tcp.flags & dpkt.tcp.TH_ECE != 0
                    features["cwr_flag_number"] += tcp.flags & dpkt.tcp.TH_CWR != 0
                elif isinstance(ip.data, dpkt.udp.UDP):
                    features["UDP"] = 1
                elif isinstance(ip.data, dpkt.icmp.ICMP):
                    features["ICMP"] = 1

                # Application Layer
                if isinstance(ip.data, dpkt.tcp.TCP):
                    tcp = ip.data
                    if tcp.sport == 80 or tcp.dport == 80:
                        features["HTTP"] = 1
                    elif tcp.sport == 443 or tcp.dport == 443:
                        features["HTTPS"] = 1
                    elif tcp.sport == 53 or tcp.dport == 53:
                        features["DNS"] = 1
                    elif tcp.sport == 23 or tcp.dport == 23:
                        features["Telnet"] = 1
                    elif tcp.sport == 25 or tcp.dport == 25:
                        features["SMTP"] = 1
                    elif tcp.sport == 22 or tcp.dport == 22:
                        features["SSH"] = 1
                    elif tcp.sport == 6667 or tcp.dport == 6667:
                        features["IRC"] = 1

            # Handle non-IP packets (e.g., ARP)
            else:
                if eth.type == dpkt.ethernet.ETH_TYPE_ARP:
                    features["ARP"] = 1

        # Handle Bluetooth packets
        elif isinstance(packet, dpkt.bluetooth.BluetoothPacket):
            # Bluetooth Layer
            bt = packet
            features["Header_Length"] = len(bt)

            # Example: You can extract specific Bluetooth fields here
            if hasattr(bt, "data"):
                features["Protocol Type"] = bt.data

        # Other features
        duration = ts - prev_ts if prev_ts else 0
        features["Duration"] = duration
        packet_counts["count"] += 1
        packet_counts["total_size"] += len(packet)
        features["Rate"] = packet_counts["total_size"] / packet_counts["count"]
        features["Srate"] = (
            packet_counts["total_size"] / duration if duration > 0 else 0
        )
        features["Drate"] = len(packet) / duration if duration > 0 else 0

    except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError) as e:
        print(f"Skipping truncated or corrupted packet: {e}")

    return features


# Function to process a single PCAP file and extract features
def process_pcap(file_path):
    features_list = []
    packet_counts = {"count": 0, "total_size": 0}
    prev_ts = None

    with open(file_path, "rb") as f:
        pcap = dpkt.pcap.Reader(f)
        for ts, packet in pcap:
            features = extract_features(packet, ts, prev_ts, packet_counts)
            prev_ts = ts
            if features:
                features_list.append(features)

    return pd.DataFrame(features_list)


# List of all PCAP files to be processed
pcap_files = [
    "CICIoMT2024/Bluetooth/profiling/pcap/Checkme_BP2A_Power.pcap",
    "CICIoMT2024/Bluetooth/profiling/pcap/SleepU_Sleep_Oxygen_Monitor_Power.pcap",
    "CICIoMT2024/Bluetooth/profiling/pcap/Lookee_Sleep_ring_Power.pcap",
    "CICIoMT2024/Bluetooth/profiling/pcap/Rhythm+_Power.pcap",
    "CICIoMT2024/Bluetooth/profiling/pcap/Lookee_O2_Ring_Power.pcap",
    "CICIoMT2024/Bluetooth/profiling/pcap/CheckmeO2_Oximeter_Power.pcap",
    "CICIoMT2024/Bluetooth/profiling/pcap/Checkme_O2_Oximeter_Power.pcap",
    "CICIoMT2024/Bluetooth/profiling/pcap/Wellue_O2_Ring_Power.pcap",
    "CICIoMT2024/Bluetooth/profiling/pcap/COOSPO_HW807_Armband_Power.pcap",
    "CICIoMT2024/Bluetooth/profiling/pcap/Powerlabs_HR_Monitor_Power.pcap",
    "CICIoMT2024/Bluetooth/attacks/pcap/test/Bluetooth_Benign_test.pcap",
    "CICIoMT2024/Bluetooth/attacks/pcap/test/Bluetooth_DoS_test.pcap",
    "CICIoMT2024/Bluetooth/attacks/pcap/train/Bluetooth_DoS_train.pcap",
    "CICIoMT2024/Bluetooth/attacks/pcap/train/Bluetooth_Benign_train.pcap",
]

# Process each PCAP file and save the extracted features to CSV
for pcap_file in pcap_files:
    print(f"Processing {pcap_file}")
    df = process_pcap(pcap_file)
    output_csv = pcap_file.replace(".pcap", ".csv")
    df.to_csv(output_csv, index=False)
    print(f"Saved {output_csv}")
