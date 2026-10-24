# TCP Protocol Simulation (Computer Networks End-Project)

A complete, self-contained **Transmission Control Protocol (TCP)** simulation written in **C++17** for Linux / WSL. This project faithfully simulates core TCP mechanisms over datagram sockets with custom TCP packet framing, providing a visual, real-time demonstration of transport layer concepts.

---

## 🌟 Key Features Demonstrated

| Requirement | Implementation Detail | Visual Indicator |
| :--- | :--- | :--- |
| **(a) 3-Way Handshake** | `SYN` (seq 100) → `SYN-ACK` (seq 300, ack 101) → `ACK` (seq 101, ack 301) | Cyan Packet Cards & Handshake logs |
| **(b) Document Exchange** | Transmits a dataset of **20 hardcoded student records** (ID, Name, Grade, Marks) | Real-time buffer tracking + Complete tabular document display |
| **(c) Internet Checksum** | RFC 1071 16-bit one's complement checksum computed for all packets; **Packet #10** undergoes simulated bit-error corruption (`checksum ^= 0xFFFF`), triggering receiver `NAK` (`FLAG_RST`) and successful retransmission | Green `[OK Valid]` vs Red `[CORRUPTED]` tags & NAK logs |
| **(d) Sliding Window** | Receiver Advertised Window (`rwnd = 4`); sender maintains in-flight buffer and slides window forward as cumulative ACKs arrive | `[WINDOW] [■ ■ ■ □] Sent: 3/4 Unacked: 3 NextSeq: 4` |
| **(e) AIMD Congestion Control** | `cwnd` starts at 1, `ssthresh` = 8. Uses Slow Start (exponential growth), Congestion Avoidance (additive increase). **Packet #5** undergoes simulated network loss triggering timeout (`select()` 500ms) → Multiplicative Decrease (`cwnd=1`, `ssthresh` halved) + Go-Back-N retransmission | `[CONGESTION] cwnd=2 ssthresh=4 → Packet #5 LOST → cwnd=1 ssthresh=2 [RETRANSMIT]` |
| **(f) 4-Way FIN Teardown** | Active close: `FIN` (seq 21) → `ACK` (ack 22) → `FIN` (seq 50) → `ACK` (ack 51) | Cyan Termination Cards & TIME-WAIT state |
| **(BONUS) RTT Estimation** | **Jacobson/Karels algorithm** (RFC 6298) tracking Sample RTT, Smoothed RTT ($SRTT$), RTT Variation ($RTTVAR$), and Retransmission Timeout ($RTO$) | `[RTT] Sample=115.2ms SRTT=112.4ms RTTVAR=8.6ms RTO=146.8ms` |

---

## 📐 Protocol Packet Framing (`TCPPacket`)

Each packet is framed using a 271-byte packed C++ structure defined in `tcp_common.h`:

```
+-----------------------------------+-----------------------------------+
|      Sequence Number (32 bits)    |   Acknowledgment Number (32 bits) |
+-----------------+-----------------+-----------------+-----------------+
|   Flags (8 bits)| Window (16 bits)| Checksum(16 bit)| Data Len(16 bit)|
+-----------------+-----------------+-----------------+-----------------+
|                                                                       |
|                     Payload Data Buffer (256 bytes)                   |
|                   (Holds serialized StudentRecord struct)             |
|                                                                       |
+-----------------------------------------------------------------------+
```

### Protocol Flags
- `FLAG_SYN  (0x01)`: Synchronize sequence numbers during connection establishment.
- `FLAG_ACK  (0x02)`: Acknowledgment field valid.
- `FLAG_FIN  (0x04)`: Connection termination request.
- `FLAG_DATA (0x08)`: Packet carries an application student record payload.
- `FLAG_RST  (0x10)`: Negative Acknowledgment (`NAK`) sent upon checksum mismatch.

---

## 🗂️ Project File Structure

- **`tcp_common.h`**: Shared protocol definitions, constants (`PORT 9090`, `WINDOW_SIZE 4`), `TCPPacket` and `StudentRecord` structures, RFC 1071 checksum calculation/verification functions, and ANSI formatting helpers.
- **`sender.cpp`**: Server role. Listens on UDP port 9090, performs 3-way handshake, manages Go-Back-N sliding window, AIMD congestion control, RTT estimation, simulates packet #5 loss & packet #10 corruption, and performs 4-way FIN teardown.
- **`receiver.cpp`**: Client role. Connects to 127.0.0.1:9090, performs 3-way handshake, verifies Internet Checksum on every packet, sends cumulative ACKs or NAKs, buffers 20 records, handles 4-way FIN teardown, and displays the final received document table.
- **`pyshark_display.py`**: Python script using PyShark to sniff loopback traffic on port 9090, parse protocol headers and hex dumps, categorize phases, and output statistics.
- **`run_demo.sh`**: Automated bash script to compile and run both sender and receiver.
- **`README.md`**: Complete documentation, architecture guide, and presentation notes.

---

## 🚀 How to Build and Run

### 1. Prerequisites (Linux / Ubuntu / WSL)
Make sure `g++` (C++17) and `make`/`bash` are available:
```bash
sudo apt update
sudo apt install -y build-essential g++
```

### 2. Automated Run (`run_demo.sh`)
Execute the automated bash demo:
```bash
cd /mnt/c/Users/gunee/Documents/cn-endproject
chmod +x run_demo.sh
./run_demo.sh
```

### 3. Manual Two-Terminal Run
To see the sender and receiver running side-by-side in separate terminals:

**Terminal 1 (Receiver / Client):**
```bash
g++ -std=c++17 -o receiver receiver.cpp -lpthread
./receiver
```

**Terminal 2 (Sender / Server):**
```bash
g++ -std=c++17 -o sender sender.cpp -lpthread
./sender
```

---

## 🔍 Running Live Traffic Sniffer (`pyshark_display.py`)

To inspect packets on the wire in real time:

1. Install prerequisites:
   ```bash
   sudo apt install -y tshark wireshark
   pip install pyshark
   ```
2. Start the sniffer in a separate terminal:
   ```bash
   python3 pyshark_display.py --interface lo --port 9090
   ```
3. Run `./run_demo.sh` in another terminal. The sniffer will capture and display:
   - Live packet timestamps and direction (`src:port → dst:port`)
   - Decoded TCP flags (`SYN`, `ACK`, `DATA`, `FIN`, `RST`)
   - Sequence, Ack, and Window metrics
   - Checksums and 32-byte hex + ASCII payload dumps
   - Detection of retransmissions and NAKs
   - Grouping by phase (Handshake → Data Transfer → Termination)
   - Final traffic summary table on completion

---

## 📊 Detailed Walkthrough of Protocol Phases

### Phase 1: 3-Way Handshake (RFC 793)
```
  Receiver (Client)                     Sender (Server)
         |                                     |
         | -------- SYN (seq=100) -----------> |  [Step 1]
         | <--- SYN-ACK (seq=300, ack=101) --- |  [Step 2]
         | -------- ACK (seq=101, ack=301) --> |  [Step 3]
         |                                     |
    [ESTABLISHED]                         [ESTABLISHED]
```

### Phase 2: Sliding Window & AIMD Congestion Control
- **Window Size ($W = 4$)**: Allows up to 4 unacknowledged packets in flight.
- **Slow Start**: `cwnd` starts at 1.0. For every successful round/ACK, `cwnd` grows exponentially (`cwnd += 1.0`) until reaching `ssthresh` (8).
- **Packet Loss Simulation (Packet #5)**:
  - Sender deliberately drops packet #5 during initial transmission.
  - Receiver receives nothing and does not ACK.
  - Sender timer expires ($RTO \ge 500\text{ms}$).
  - **Multiplicative Decrease**: `ssthresh` is halved to $\max(2, cwnd / 2) = 2$, and `cwnd` resets to 1.
  - Sender retransmits packet #5 via Go-Back-N. Packet #5 is received, ACKed, and transmission resumes.
- **Checksum Error Simulation (Packet #10)**:
  - Sender inverts the checksum bits of packet #10 (`checksum ^= 0xFFFF`).
  - Receiver calculates RFC 1071 checksum; detects corruption.
  - Receiver discards packet and returns a `NAK` (`FLAG_RST` with `ack_num = 10`).
  - Sender intercepts `NAK`, recalculates the valid checksum, and retransmits packet #10.
  - Receiver validates the retransmitted packet and returns `ACK #10`.

### Phase 3: Jacobson/Karels RTT Estimation (RFC 6298)
For each acknowledged data packet:
1. Sample RTT ($M$) is calculated: $M = \text{Elapsed Time}(\text{ACK received} - \text{Packet sent})$.
2. Error is computed: $Err = M - SRTT$.
3. Smoothed RTT ($SRTT$) updated with filter $\alpha = 0.125$:
   $$SRTT \leftarrow 0.875 \cdot SRTT + 0.125 \cdot M$$
4. RTT Variation ($RTTVAR$) updated with filter $\beta = 0.25$:
   $$RTTVAR \leftarrow 0.75 \cdot RTTVAR + 0.25 \cdot |Err|$$
5. Retransmission Timeout ($RTO$) is adjusted:
   $$RTO \leftarrow SRTT + 4 \cdot RTTVAR$$

### Phase 4: 4-Way Connection Teardown
```
  Sender (Active Close)                 Receiver (Passive Close)
         |                                     |
         | -------- FIN (seq=21) ------------> |  [Step 1]
         | <------- ACK (ack=22) ------------- |  [Step 2]
         | <------- FIN (seq=50) ------------- |  [Step 3]
         | -------- ACK (ack=51) ------------> |  [Step 4]
         |                                     |
    [TIME-WAIT]                             [CLOSED]
```

---

## 🎓 University Presentation Notes (Q&A Cheatsheet)

1. **Why simulate TCP over UDP datagrams rather than using raw sockets or OS TCP?**
   - *Raw sockets* (`SOCK_RAW`) require root / administrator privileges (`sudo`), making demonstrations fragile.
   - *Operating System TCP* already handles retransmissions, cumulative ACKs, and flow control in kernel space, masking our simulation logic.
   - Using *UDP datagrams* gives us an unreliable packet abstraction without OS interference, allowing custom simulation of timeouts, bit corruption, sliding window, and AIMD in user space.
2. **How does the 16-bit Internet Checksum work?**
   - The packet header and payload are treated as a sequence of 16-bit integers. They are summed using one's complement arithmetic (end-around carry). The final sum is inverted.
3. **What is the difference between Slow Start and Congestion Avoidance?**
   - During Slow Start ($cwnd < ssthresh$), the window grows exponentially to probe available capacity quickly. During Congestion Avoidance ($cwnd \ge ssthresh$), the window grows linearly (Additive Increase, +1 MSS per RTT) to prevent congestion collapse.
4. **Why is Jacobson/Karels algorithm needed instead of a simple average?**
   - Simple average cannot respond quickly to network variance. Jacobson/Karels tracks variance ($RTTVAR$) alongside smoothed mean ($SRTT$), ensuring $RTO$ expands safely under high jitter to avoid spurious retransmissions.
