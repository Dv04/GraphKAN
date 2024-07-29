import dpkt
import pandas as pd


def extract_features(packet):
    eth = dpkt.ethernet.Ethernet(packet)
    ip = eth.data

    # Initialize feature dictionary
    features = {
        "Header_Length": len(eth),
        "Protocol Type": ip.p if isinstance(ip, dpkt.ip.IP) else None,
        "TCP": 0,
        "UDP": 0,
        "ICMP": 0,
        "HTTP": 0,
        "HTTPS": 0,
        "DNS": 0,
        "Telnet": 0,
        "SMTP": 0,
        "SSH": 0,
        "IRC": 0,
    }

    # Transport Layer
    if isinstance(ip, dpkt.tcp.TCP):
        features["TCP"] = 1
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
    elif isinstance(ip, dpkt.udp.UDP):
        features["UDP"] = 1
    elif isinstance(ip, dpkt.icmp.ICMP):
        features["ICMP"] = 1

    return features


def process_pcap(file_path):
    features_list = []

    with open(file_path, "rb") as f:
        pcap = dpkt.pcap.Reader(f)
        for ts, packet in pcap:
            try:
                features = extract_features(packet)
                features_list.append(features)
            except Exception as e:
                print(f"Skipping packet due to error: {e}")

    return pd.DataFrame(features_list)


def compare_pcap_csv(pcap_file, csv_file):
    # Process PCAP file
    df_pcap = process_pcap(pcap_file)

    # Load CSV file
    df_csv = pd.read_csv(csv_file)

    # Compare the structures
    print("PCAP DataFrame head:")
    print(df_pcap.head())
    print("PCAP DataFrame shape:", df_pcap.shape)

    print("\nCSV DataFrame head:")
    print(df_csv.head())
    print("CSV DataFrame shape:", df_csv.shape)

    # Compare the data
    if df_pcap.equals(df_csv):
        print("\nThe PCAP and CSV files are consistent.")
    else:
        print("\nThe PCAP and CSV files are not consistent. Differences:")
        print(df_pcap.compare(df_csv))


# File paths
pcap_file = "CICIoMT2024/Bluetooth/attacks/pcap/test/Bluetooth_Benign_test.pcap"
csv_file = "CICIoMT2024/Bluetooth/attacks/csv/test/Bluetooth_Benign_test.csv"

# Run comparison
compare_pcap_csv(pcap_file, csv_file)
