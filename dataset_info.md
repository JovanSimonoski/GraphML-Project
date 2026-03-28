# CIC-IDS2017 - Intrusion Detection Evaluation Dataset

This is the **CICIDS2017** dataset from the Canadian Institute for Cybersecurity. It contains network traffic captured over 5 days (Mon July 3 - Fri July 7, 2017), with benign traffic and various real-world attacks.

---

## What Each Row Represents

**Each row is a single network flow** - a bidirectional sequence of packets between a source IP:port and a destination IP:port using a specific protocol. Flows are extracted from raw PCAP files using **CICFlowMeter**, which aggregates packets into flows and computes statistical features.

---

## The Two Directories

### MachineLearningCVE (79 columns, 2,830,743 rows total)

- **Stripped of identifying information** - no Flow ID, Source/Destination IPs, Protocol number, or Timestamp columns.
- Designed for **pure ML training** where you only use flow features + label.

### TrafficLabelling (85 columns, 3,119,345 rows total)

- **Contains 6 additional identifying columns** at the start:
  - **Flow ID** - unique identifier like `192.168.10.5-104.16.207.165-54865-443-6`
  - **Source IP** - originating IP address
  - **Source Port** - originating port
  - **Destination IP** - destination IP address
  - **Destination Port** - destination port number
  - **Protocol** - IP protocol number (6 = TCP, 17 = UDP, etc.)
  - **Timestamp** - when the flow was recorded (e.g., `7/7/2017 3:30`)
- The TrafficLabelling version has ~288K more rows (mostly in Thursday-Morning-WebAttacks: 458,968 vs 170,366), likely because additional flows were retained before filtering.
- All 79 feature columns are identical between the two directories.

---

## Column-by-Column Explanation (the 79 shared feature columns)

### Flow Identification (TrafficLabelling only)

| Column | Description |
|---|---|
| Flow ID | Concatenation of src_ip-dst_ip-src_port-dst_port-protocol |
| Source IP | IP address that initiated the flow |
| Source Port | TCP/UDP port of the source |
| Destination IP | IP address of the destination |
| Destination Port | TCP/UDP port of the destination |
| Protocol | IANA protocol number (6=TCP, 17=UDP) |
| Timestamp | Date/time of the flow start |

### Packet Counts & Sizes

| Column | Description |
|---|---|
| Flow Duration | Duration of the flow in microseconds |
| Total Fwd Packets | Total packets in the forward direction (src -> dst) |
| Total Backward Packets | Total packets in the backward direction (dst -> src) |
| Total Length of Fwd Packets | Total size (bytes) of packets in forward direction |
| Total Length of Bwd Packets | Total size (bytes) of packets in backward direction |

### Forward Packet Length Statistics

| Column | Description |
|---|---|
| Fwd Packet Length Max | Maximum packet payload size in forward direction |
| Fwd Packet Length Min | Minimum packet payload size in forward direction |
| Fwd Packet Length Mean | Mean packet payload size in forward direction |
| Fwd Packet Length Std | Standard deviation of forward packet sizes |

### Backward Packet Length Statistics

| Column | Description |
|---|---|
| Bwd Packet Length Max | Maximum packet payload size in backward direction |
| Bwd Packet Length Min | Minimum packet payload size in backward direction |
| Bwd Packet Length Mean | Mean packet payload size in backward direction |
| Bwd Packet Length Std | Standard deviation of backward packet sizes |

### Flow Rate Features

| Column | Description |
|---|---|
| Flow Bytes/s | Number of bytes per second in the flow |
| Flow Packets/s | Number of packets per second in the flow |

### Inter-Arrival Time (IAT) Features

IAT = time between consecutive packets. These capture the **timing behavior** of the flow.

| Column | Description |
|---|---|
| Flow IAT Mean | Mean inter-arrival time across the entire flow |
| Flow IAT Std | Standard deviation of inter-arrival times across the entire flow |
| Flow IAT Max | Maximum inter-arrival time across the entire flow |
| Flow IAT Min | Minimum inter-arrival time across the entire flow |
| Fwd IAT Total | Total inter-arrival time for forward-direction packets |
| Fwd IAT Mean | Mean IAT for forward-direction packets |
| Fwd IAT Std | Std deviation of IAT for forward-direction packets |
| Fwd IAT Max | Maximum IAT for forward-direction packets |
| Fwd IAT Min | Minimum IAT for forward-direction packets |
| Bwd IAT Total | Total inter-arrival time for backward-direction packets |
| Bwd IAT Mean | Mean IAT for backward-direction packets |
| Bwd IAT Std | Std deviation of IAT for backward-direction packets |
| Bwd IAT Max | Maximum IAT for backward-direction packets |
| Bwd IAT Min | Minimum IAT for backward-direction packets |

### TCP Flag Features

| Column | Description |
|---|---|
| Fwd PSH Flags | Number of PSH flags set in forward packets |
| Bwd PSH Flags | Number of PSH flags in backward packets |
| Fwd URG Flags | Number of URG flags in forward packets |
| Bwd URG Flags | Number of URG flags in backward packets |
| FIN Flag Count | Number of FIN flags in the flow |
| SYN Flag Count | Number of SYN flags |
| RST Flag Count | Number of RST flags |
| PSH Flag Count | Number of PSH flags (total) |
| ACK Flag Count | Number of ACK flags |
| URG Flag Count | Number of URG flags (total) |
| CWE Flag Count | Number of CWR (Congestion Window Reduced) flags |
| ECE Flag Count | Number of ECE (ECN-Echo) flags |

### Header Length

| Column | Description |
|---|---|
| Fwd Header Length | Total bytes used by headers in forward direction |
| Bwd Header Length | Total bytes used by headers in backward direction |
| Fwd Header Length.1 | Duplicate / alternate calculation of forward header length |

### Packet Rate

| Column | Description |
|---|---|
| Fwd Packets/s | Forward packets per second |
| Bwd Packets/s | Backward packets per second |

### Overall Packet Length Stats

| Column | Description |
|---|---|
| Min Packet Length | Smallest packet in the entire flow |
| Max Packet Length | Largest packet in the entire flow |
| Packet Length Mean | Mean packet length across the flow |
| Packet Length Std | Standard deviation of packet lengths |
| Packet Length Variance | Variance of packet lengths |

### Ratio & Average Features

| Column | Description |
|---|---|
| Down/Up Ratio | Ratio of backward to forward packets |
| Average Packet Size | Mean size of all packets (fwd+bwd) |
| Avg Fwd Segment Size | Average segment size in forward direction (≈ Fwd Packet Length Mean) |
| Avg Bwd Segment Size | Average segment size in backward direction |

### Bulk Transfer Features

| Column | Description |
|---|---|
| Fwd Avg Bytes/Bulk | Average bytes per bulk transfer in forward direction |
| Fwd Avg Packets/Bulk | Average packets per bulk in forward direction |
| Fwd Avg Bulk Rate | Average bulk rate in forward direction |
| Bwd Avg Bytes/Bulk | Average bytes per bulk transfer in backward direction |
| Bwd Avg Packets/Bulk | Average packets per bulk in backward direction |
| Bwd Avg Bulk Rate | Average bulk rate in backward direction |

### Subflow Features

| Column | Description |
|---|---|
| Subflow Fwd Packets | Average packets in a sub-flow (forward) |
| Subflow Fwd Bytes | Average bytes in a sub-flow (forward) |
| Subflow Bwd Packets | Average packets in a sub-flow (backward) |
| Subflow Bwd Bytes | Average bytes in a sub-flow (backward) |

### TCP Window & Segment Features

| Column | Description |
|---|---|
| Init_Win_bytes_forward | Initial TCP window size in forward direction (-1 if not TCP) |
| Init_Win_bytes_backward | Initial TCP window size in backward direction (-1 if not TCP) |
| act_data_pkt_fwd | Count of packets with at least 1 byte of TCP payload in forward direction |
| min_seg_size_forward | Minimum segment size observed in forward direction |

### Active/Idle Time Features

| Column | Description |
|---|---|
| Active Mean | Mean time the flow was actively sending data before going idle |
| Active Std | Std deviation of active times |
| Active Max | Maximum active time |
| Active Min | Minimum active time |
| Idle Mean | Mean time the flow was idle before becoming active again |
| Idle Std | Std deviation of idle times |
| Idle Max | Maximum idle time |
| Idle Min | Minimum idle time |

### Label (Target Variable)

| Column | Description |
|---|---|
| Label | Classification label - either `BENIGN` or a specific attack type |

---

## Label Distribution (identical in both directories)

| Label | Count | % of Total |
|---|---|---|
| BENIGN | 2,273,097 | 80.3% |
| DoS Hulk | 231,073 | 8.2% |
| PortScan | 158,930 | 5.6% |
| DDoS | 128,027 | 4.5% |
| DoS GoldenEye | 10,293 | 0.36% |
| FTP-Patator | 7,938 | 0.28% |
| SSH-Patator | 5,897 | 0.21% |
| DoS slowloris | 5,796 | 0.20% |
| DoS Slowhttptest | 5,499 | 0.19% |
| Bot | 1,966 | 0.07% |
| Web Attack - Brute Force | 1,507 | 0.05% |
| Web Attack - XSS | 652 | 0.02% |
| Infiltration | 36 | ~0% |
| Web Attack - SQL Injection | 21 | ~0% |
| Heartbleed | 11 | ~0% |

---

## Files by Day

| File | Day | Attack Content | Rows |
|---|---|---|---|
| Monday-WorkingHours | Mon Jul 3 | Benign only | 529,918 |
| Tuesday-WorkingHours | Tue Jul 4 | FTP-Patator, SSH-Patator | 445,909 |
| Wednesday-workingHours | Wed Jul 5 | DoS/DDoS variants, Heartbleed | 692,703 |
| Thursday-Morning-WebAttacks | Thu Jul 6 AM | Web Attack Brute Force, XSS, SQL Injection | 170,366 (ML) / 458,968 (TL) |
| Thursday-Afternoon-Infilteration | Thu Jul 6 PM | Infiltration attacks | 288,602 |
| Friday-Morning | Fri Jul 7 AM | Botnet ARES | 191,033 |
| Friday-Afternoon-PortScan | Fri Jul 7 PM | Port scanning | 286,467 |
| Friday-Afternoon-DDos | Fri Jul 7 PM | DDoS LOIT | 225,745 |

---

## Key Takeaways

1. **Use MachineLearningCVE** if you only need features + labels for ML classification (no IP/port info needed).
2. **Use TrafficLabelling** if you need network topology context (IPs, ports, timestamps) - essential for **graph-based ML** where nodes are IPs and edges are flows.
3. The dataset is **heavily imbalanced** - ~80% benign. Some attack classes (Heartbleed, SQL Injection, Infiltration) have extremely few samples.
4. All features are computed by **CICFlowMeter** from raw PCAPs - they capture packet-level, flow-level, and timing statistics.

---

## Citation

> Iman Sharafaldin, Arash Habibi Lashkari, and Ali A. Ghorbani, "Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization", 4th International Conference on Information Systems Security and Privacy (ICISSP), Portugal, January 2018.
