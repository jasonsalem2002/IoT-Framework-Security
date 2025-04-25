import pyshark
import csv
import time
import numpy as np
import pandas as pd
import joblib
from datetime import datetime
import traceback



# FLOW STATS

flows = {}  # flows[(src, sport, dst, dport, proto)] = {...} stats

def initialize_flow_data():
    """
    Initializes a new flow
    """
    return {
        "timestamps": [],
        "start_time": 0.0,

        # For the final features:
        "packet_sizes": [],       # store length of each packet (entire flow)
        "packet_timestamps": [],  # store times to compute IAT
        "flow_duration": 0.0,

        # If you want separate inbound/outbound stats:
        "inbound_sizes":  [],
        "outbound_sizes": [],

        # counters to track how many times each flag has appeared
        "ack_count": 0,
        "syn_count": 0,
        "fin_count": 0,
        "urg_count": 0,
        "rst_count": 0,

        # total packet count (flow size)
        "packet_count": 0,
        # might also store inbound_packet_count, outbound_packet_count, etc.
        "inbound_count": 0,
        "outbound_count": 0,

        # last packet timestamp to compute IAT
        "last_ts": None,
    }

def get_flow_key(packet):
    """
    Return a flow key (src_ip, src_port, dst_ip, dst_port, protocol).
    protocol: 6 for TCP, 17 for UDP, 1 for ICMP...
    """
    try:
        # IP layer
        src_ip = packet.ip.src
        dst_ip = packet.ip.dst
        proto  = int(packet.ip.proto)
    except:
        # check if IPv6
        if hasattr(packet, 'ipv6'):
            src_ip = packet.ipv6.src
            dst_ip = packet.ipv6.dst
            proto  = int(packet.ipv6.nxt) 
        else:
            return None

    # Ports
    if hasattr(packet, 'tcp'):
        src_port = int(packet.tcp.srcport)
        dst_port = int(packet.tcp.dstport)
        protocol = 6
    elif hasattr(packet, 'udp'):
        src_port = int(packet.udp.srcport)
        dst_port = int(packet.udp.dstport)
        protocol = 17
    elif hasattr(packet, 'icmp'):
        src_port = 0
        dst_port = 0
        protocol = 1
    else:
        src_port = 0
        dst_port = 0
        protocol = proto

    return (src_ip, src_port, dst_ip, dst_port, protocol)

def update_flow_times(flow_data, this_timestamp):
    """
    Update the flow_duration and keep track of timestamps for IAT
    """
    flow_data["packet_timestamps"].append(this_timestamp)
    flow_data["packet_count"] += 1
    if len(flow_data["packet_timestamps"]) == 1:    # If first packet in flow
        flow_data["start_time"] = this_timestamp
        flow_data["flow_duration"] = 0.0
        flow_data["last_ts"] = this_timestamp
    else:
        flow_data["flow_duration"] = this_timestamp - flow_data["start_time"]

def process_flags_and_direction(flow_data, packet, flow_key):
    """
    - Get the flags for the current packet (0/1).
    - Increment ack_count, etc., if the current packet has the flag set.
    - Determine inbound/outbound by comparing IPs to the flow key's original src/dst.
    """
    # Find if inbound or outbound (wrt original direction)
    this_src_ip = flow_key[0]
    if hasattr(packet, 'ip'):
        current_src_ip = packet.ip.src
    elif hasattr(packet, 'ipv6'):
        current_src_ip = packet.ipv6.src
    else:
        current_src_ip = None

    is_outbound = (current_src_ip == this_src_ip)

    if is_outbound:
        flow_data["outbound_count"] += 1
    else:
        flow_data["inbound_count"] += 1

    # TCP flags for this packet (1 if this packet has that flag, 0 if not)
    fin_flag_number = 0
    syn_flag_number = 0
    rst_flag_number = 0
    psh_flag_number = 0
    ack_flag_number = 0
    ece_flag_number = 0
    cwr_flag_number = 0

    if hasattr(packet, 'tcp'):
        tcp_layer = packet.tcp
        fin_flag_number = 1 if tcp_layer.flags_fin == 'True' else 0
        syn_flag_number = 1 if tcp_layer.flags_syn == 'True' else 0
        rst_flag_number = 1 if tcp_layer.flags_reset == 'True' else 0
        psh_flag_number = 1 if tcp_layer.flags_push == 'True' else 0
        ack_flag_number = 1 if tcp_layer.flags_ack == 'True' else 0
        ece_flag_number = 1 if tcp_layer.flags_ece == 'True' else 0
        cwr_flag_number = 1 if tcp_layer.flags_cwr == 'True' else 0

    # Also increment the flow-wide counters for every flag
    if ack_flag_number == 1:
        flow_data["ack_count"] += 1
    if syn_flag_number == 1:
        flow_data["syn_count"] += 1
    if fin_flag_number == 1:
        flow_data["fin_count"] += 1
    if rst_flag_number == 1:
        flow_data["rst_count"] += 1
    if hasattr(packet, 'tcp') and packet.tcp.flags_urg == 'True':
        flow_data["urg_count"] += 1

    return (fin_flag_number, syn_flag_number, rst_flag_number,
            psh_flag_number, ack_flag_number, ece_flag_number, cwr_flag_number)

def process_packet_size(flow_data, packet, is_outbound):
    """
    Get the current packet length (total captured frame length: Ethernet + IP + ...)
    """
    length = int(packet.length) if hasattr(packet, 'length') else 0
    flow_data["packet_sizes"].append(length)

    if is_outbound:
        flow_data["outbound_sizes"].append(length)
    else:
        flow_data["inbound_sizes"].append(length)

    return length

def compute_iat_for_this_packet(flow_data, this_timestamp):
    """
    IAT is the time difference between the current packet and the previous one in the flow
    """
    if flow_data["last_ts"] is None:
        return 0.0
    iat = this_timestamp - flow_data["last_ts"]
    # Update last timestamp
    flow_data["last_ts"] = this_timestamp
    return iat

# Load model
with open('model/LogisticRegression_8_classes.pkl', 'rb') as f:
    model = joblib.load(f)

# Load scaler
with open('model/scaler copy.pkl', 'rb') as f:
    loaded_scaler = joblib.load(f)


def build_feature_row(pkt_dict):
    """
    Create a single-row DataFrame with the 47 columns in the correct order.
    The 'label' column can remain a dummy if your model was trained w/o it.
    """
    features = [  # All features expected by the model
        'flow_duration','Header_Length','Protocol Type','Duration','Rate','Srate','Drate',
        'fin_flag_number','syn_flag_number','rst_flag_number','psh_flag_number','ack_flag_number',
        'ece_flag_number','cwr_flag_number','ack_count','syn_count','fin_count','urg_count','rst_count',
        'HTTP','HTTPS','DNS','Telnet','SMTP','SSH','IRC','TCP','UDP','DHCP','ARP','ICMP','IPv','LLC',
        'Tot sum','Min','Max','AVG','Std','Tot size','IAT','Number','Magnitue','Radius','Covariance',
        'Variance','Weight','label'
    ]

    row = {}
    for c in features:
        row[c] = pkt_dict.get(c, 0.0)

    df = pd.DataFrame([[row[c] for c in features]], columns=features)
    # df.drop(columns=['label'], inplace=True)

    return df.replace([np.inf, -np.inf], np.nan).fillna(0.0)

def predict_packet(pkt_dict):
    df = build_feature_row(pkt_dict)
    X = df.drop(columns=['label']).values  
    X_scaled = loaded_scaler.transform(X)
    y_pred = model.predict(X_scaled)

    # print(df.keys())
    # print(X)
    return y_pred[0] 


def process_packet(packet, flow_key):
    """
    Using the flow_key and the global flows[] data, fill in the 47 columns.
    """
    fdata = flows[flow_key]
    sniff_time = packet.sniff_time
    if not sniff_time:
        return None

    this_ts = sniff_time.timestamp()
    update_flow_times(fdata, this_ts)
    iat = compute_iat_for_this_packet(fdata, this_ts)
    (fin_flag, syn_flag, rst_flag, psh_flag, ack_flag, ece_flag, cwr_flag) = process_flags_and_direction(fdata, packet, flow_key)

    # is_outbound?
    if hasattr(packet, 'ip'):
        is_outbound = (packet.ip.src == flow_key[0])
    elif hasattr(packet, 'ipv6'):
        is_outbound = (packet.ipv6.src == flow_key[0])
    else:
        is_outbound = True

    pkt_len = process_packet_size(fdata, packet, is_outbound)

    # Now build the final dict of 47 features
    pkt_dict = {}
    # 2) flow_duration
    pkt_dict["flow_duration"] = fdata["flow_duration"]
    # 3) Header_Length
    pkt_dict["Header_Length"] = float(packet.length) if hasattr(packet, 'length') else 0.0
    # 4) Protocol Type
    pkt_dict["Protocol Type"] = flow_key[4]
    # 5) Duration => TTL
    if hasattr(packet, 'ip'):
        pkt_dict["Duration"] = float(packet.ip.ttl)
    elif hasattr(packet, 'ipv6'):
        pkt_dict["Duration"] = float(packet.ipv6.hlim)
    else:
        pkt_dict["Duration"] = 0.0
    # 6) Rate
    dur = fdata["flow_duration"] if fdata["flow_duration"]>0 else 1e-9
    pkt_dict["Rate"] = fdata["packet_count"] / dur
    # 7) Srate
    pkt_dict["Srate"] = fdata["outbound_count"] / dur
    # 8) Drate
    pkt_dict["Drate"] = fdata["inbound_count"] / dur
    # 9-15) per-packet flags
    pkt_dict["fin_flag_number"] = fin_flag
    pkt_dict["syn_flag_number"] = syn_flag
    pkt_dict["rst_flag_number"] = rst_flag
    pkt_dict["psh_flag_number"] = psh_flag
    pkt_dict["ack_flag_number"] = ack_flag
    pkt_dict["ece_flag_number"] = ece_flag
    pkt_dict["cwr_flag_number"] = cwr_flag
    # 16..20) flow-wide counters
    pkt_dict["ack_count"] = fdata["ack_count"]
    pkt_dict["syn_count"] = fdata["syn_count"]
    pkt_dict["fin_count"] = fdata["fin_count"]
    pkt_dict["urg_count"] = fdata["urg_count"]
    pkt_dict["rst_count"] = fdata["rst_count"]
    # 21..34) protocol bits
    src_p, dst_p = flow_key[1], flow_key[3]
    ports = [src_p, dst_p] if src_p and dst_p else []
    pkt_dict["HTTP"]  = 1.0 if 80 in ports else 0.0
    pkt_dict["HTTPS"] = 1.0 if 443 in ports else 0.0
    pkt_dict["DNS"]   = 1.0 if 53 in ports else 0.0
    pkt_dict["Telnet"] = 1.0 if 23 in ports else 0.0
    pkt_dict["SMTP"]   = 1.0 if 25 in ports else 0.0
    pkt_dict["SSH"]    = 1.0 if 22 in ports else 0.0
    pkt_dict["IRC"]    = 1.0 if 194 in ports else 0.0
    pkt_dict["TCP"]    = 1.0 if flow_key[4] == 6 else 0.0
    pkt_dict["UDP"]    = 1.0 if flow_key[4] == 17 else 0.0
    pkt_dict["DHCP"]   = 1.0 if (67 in ports or 68 in ports) else 0.0
    pkt_dict["ARP"]    = 1.0 if hasattr(packet, 'arp') else 0.0
    pkt_dict["ICMP"]   = 1.0 if flow_key[4] == 1 else 0.0
    if hasattr(packet, 'ip') or hasattr(packet, 'ipv6'):
        pkt_dict["IPv"] = 1.0
    else:
        pkt_dict["IPv"] = 0.0
    pkt_dict["LLC"] = 0.0
    # 35..39) Tot sum, Min, Max, AVG, Std
    sizes = fdata["packet_sizes"]
    if sizes:
        pkt_dict["Tot sum"] = sum(sizes)
        pkt_dict["Min"]     = min(sizes)
        pkt_dict["Max"]     = max(sizes)
        pkt_dict["AVG"]     = np.mean(sizes)
        pkt_dict["Std"]     = np.std(sizes)
    else:
        pkt_dict["Tot sum"] = 0
        pkt_dict["Min"]     = 0
        pkt_dict["Max"]     = 0
        pkt_dict["AVG"]     = 0
        pkt_dict["Std"]     = 0

    pkt_dict["Tot size"] = pkt_len
    pkt_dict["IAT"] = iat
    pkt_dict["Number"] = fdata["packet_count"]
    in_mean  = np.mean(fdata["inbound_sizes"])  if fdata["inbound_sizes"] else 0
    out_mean = np.mean(fdata["outbound_sizes"]) if fdata["outbound_sizes"] else 0
    pkt_dict["Magnitue"] = (in_mean + out_mean)*0.5
    in_var  = np.var(fdata["inbound_sizes"])  if len(fdata["inbound_sizes"])>1 else 0
    out_var = np.var(fdata["outbound_sizes"]) if len(fdata["outbound_sizes"])>1 else 0
    pkt_dict["Radius"] = 0.5*(in_var + out_var)
    if len(fdata["inbound_sizes"])>1 and len(fdata["outbound_sizes"])>1:
        ml = min(len(fdata["inbound_sizes"]), len(fdata["outbound_sizes"]))
        cov = np.cov(
            fdata["inbound_sizes"][:ml],
            fdata["outbound_sizes"][:ml]
        )[0,1]
    else:
        cov = 0
    pkt_dict["Covariance"] = cov
    pkt_dict["Variance"] = np.var(sizes) if len(sizes)>1 else 0
    pkt_dict["Weight"] = fdata["inbound_count"] * fdata["outbound_count"]

    return pkt_dict



def process(target_ip,
            interface = "Wi-Fi"):
    """
    Capture traffic and process, predict, and store in database.
    * Only for packets that involve a certain IP address target_ip.
    """
    print("IN PROCESS...")

    cap = pyshark.LiveCapture(
        interface=interface,
        tshark_path="c:/Program Files/Wireshark/tshark.exe",
        bpf_filter=f"host {target_ip}"  # Filter 
    )

    print(f"Listening on {interface} for traffic involving {target_ip}...")

    # Setup writing to csv
    out_csv = "modelData/data2.csv"
    f = open(out_csv, 'w', newline='', encoding='utf-8')
    writer = None
    all_fields = []

    try:
        for packet in cap.sniff_continuously():
            print("Packet processing...")
            # print(packet)

            ip_layer = getattr(packet, "ip", None) or getattr(packet, "ipv6", None)
            if not ip_layer:
                continue 

            src = ip_layer.src
            dst = ip_layer.dst
            if src != target_ip and dst != target_ip: 
                continue

            flow_key = get_flow_key(packet)
            if not flow_key:
                continue

            if flow_key not in flows:
                flows[flow_key] = initialize_flow_data()

            # Build the feature dict for this packet
            pkt_dict = process_packet(packet, flow_key)
            if not pkt_dict:
                continue

            # Timestamp
            pkt_dict["timestamp"] = packet.sniff_time.timestamp()

            # Get IP addresses
            pkt_dict["src_ip"] = src
            pkt_dict["dst_ip"] = dst
            
            if hasattr(packet, 'eth'):
                pkt_dict["src_mac"] = packet.eth.src
                pkt_dict["dst_mac"] = packet.eth.dst

            # Predict
            pred_cat = predict_packet(pkt_dict)
            pkt_dict["predicted_label"] = "Normal" if pred_cat=="Benign" else "Anomaly"
            pkt_dict["predicted_cat"] = pred_cat

            # Write to csv
            new_cols = set(pkt_dict.keys()) - set(all_fields)
            if new_cols:
                all_fields = sorted(list(set(all_fields) | set(pkt_dict.keys())))
                if writer is not None:
                    f.close()
                    f = open(out_csv, 'w', newline='', encoding='utf-8')
                writer = csv.DictWriter(f, fieldnames=all_fields)
                writer.writeheader()

            if writer is None:
                all_fields = sorted(pkt_dict.keys())
                writer = csv.DictWriter(f, fieldnames=all_fields)
                writer.writeheader()

            row = {c: pkt_dict.get(c, '') for c in all_fields}
            writer.writerow(row)
            f.flush()

            print(f"Processed packet => predicted: {pred_cat}")

    except Exception as e:
        # Never let a bad packet kill the loop
        print(f"[pipeline] error: {e}")
        traceback.print_exc()
    finally:
        cap.close()
        f.close()
        print(f"CSV saved to {out_csv}.")