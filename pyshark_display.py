#!/usr/bin/env python3
"""
================================================================================
TCP Protocol Simulation - Real-Time Packet Sniffer & Analyzer (PyShark)
================================================================================
Demonstrates network packet inspection on port 9090 for university CN presentation.
Captures live packets, unpacks TCP fields, groups traffic by protocol phase,
and tracks retransmissions, ACKs, and window metrics.
================================================================================
"""

import sys
import struct
import argparse
from datetime import datetime

# ANSI Color Codes for Terminal Output
class Colors:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    RED     = "\033[1;31m"
    GREEN   = "\033[1;32m"
    YELLOW  = "\033[1;33m"
    BLUE    = "\033[1;34m"
    MAGENTA = "\033[1;35m"
    CYAN    = "\033[1;36m"
    WHITE   = "\033[1;37m"

FLAG_SYN  = 0x01
FLAG_ACK  = 0x02
FLAG_FIN  = 0x04
FLAG_DATA = 0x08
FLAG_RST  = 0x10

def format_flags(flags):
    names = []
    if flags & FLAG_SYN:  names.append("SYN")
    if flags & FLAG_ACK:  names.append("ACK")
    if flags & FLAG_FIN:  names.append("FIN")
    if flags & FLAG_DATA: names.append("DATA")
    if flags & FLAG_RST:  names.append("RST/NAK")
    return " | ".join(names) if names else "NONE"

def hex_dump(data_bytes, max_bytes=32):
    """Formats payload bytes into hex and printable ASCII."""
    sub = data_bytes[:max_bytes]
    hex_str = " ".join(f"{b:02X}" for b in sub)
    ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in sub)
    return f"{hex_str:<96} | {ascii_str}"

def determine_phase(flags, seq_num, total_seen):
    if flags & FLAG_SYN:
        return "1. Connection Establishment (Handshake)"
    elif flags & FLAG_FIN:
        return "3. Connection Termination (Teardown)"
    elif flags & (FLAG_DATA | FLAG_ACK | FLAG_RST):
        return "2. Data Transfer & Congestion Control"
    return "Unknown Phase"

def parse_simulated_tcp(raw_payload):
    """
    Unpacks struct TCPPacket:
    struct TCPPacket {
        uint32_t seq_num;     // 4 bytes
        uint32_t ack_num;     // 4 bytes
        uint8_t  flags;       // 1 byte
        uint16_t window_size; // 2 bytes
        uint16_t checksum;    // 2 bytes
        uint16_t data_len;    // 2 bytes
        char     data[256];   // 256 bytes
    };
    """
    if len(raw_payload) < 15:
        return None
    try:
        # Check little-endian first
        seq, ack, flags, win, csum, data_len = struct.unpack_from("<IIBHHH", raw_payload, 0)
        # Sanity check: valid flags
        if flags & ~(FLAG_SYN | FLAG_ACK | FLAG_FIN | FLAG_DATA | FLAG_RST):
            # Try big-endian
            seq, ack, flags, win, csum, data_len = struct.unpack_from(">IIBHHH", raw_payload, 0)

        payload_data = raw_payload[15:15 + data_len] if len(raw_payload) >= 15 + data_len else raw_payload[15:]
        return {
            "seq": seq,
            "ack": ack,
            "flags": flags,
            "window": win,
            "checksum": csum,
            "data_len": data_len,
            "data": payload_data
        }
    except Exception:
        return None

def main():
    parser = argparse.ArgumentParser(description="Live TCP Simulation Packet Sniffer using PyShark")
    parser.add_argument("-i", "--interface", default="lo", help="Capture interface (default: lo)")
    parser.add_argument("-p", "--port", type=int, default=9090, help="Port to sniff (default: 9090)")
    args = parser.parse_args()

    print(f"{Colors.CYAN}{Colors.BOLD}")
    print("╔══════════════════════════════════════════════════════════════════╗")
    print("║     PYSHARK TCP PACKET SNIFFER & PROTOCOL ANALYZER               ║")
    print(f"║     Interface: {args.interface:<10}  |  Filter: port {args.port:<6}                    ║")
    print("╚══════════════════════════════════════════════════════════════════╝")
    print(f"{Colors.RESET}")

    try:
        import pyshark
    except ImportError:
        print(f"{Colors.RED}[ERROR] 'pyshark' library not found!{Colors.RESET}")
        print("To run this analyzer, install PyShark and TShark:")
        print("  pip install pyshark")
        print("  sudo apt-get install tshark (on Ubuntu/Debian)")
        print("\nDisplaying analyzer specification and exiting cleanly.")
        return 0

    # Statistics tracking
    stats = {
        "total": 0,
        "handshake": 0,
        "data": 0,
        "acks": 0,
        "retransmissions": 0,
        "naks": 0,
        "termination": 0
    }
    seen_seqs = set()
    current_phase = None

    bpf = f"port {args.port}"
    print(f"{Colors.GREEN}[STATUS] Starting live capture on '{args.interface}' with BPF filter '{bpf}'...{Colors.RESET}")
    print(f"{Colors.YELLOW}[INFO] Press Ctrl+C at any time to display traffic summary statistics.{Colors.RESET}\n")

    try:
        capture = pyshark.LiveCapture(interface=args.interface, bpf_filter=bpf)
        for pkt in capture.sniff_continuously():
            stats["total"] += 1
            timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]

            # Determine transport layer (TCP or UDP carrying simulated TCP)
            src_port = "Unknown"
            dst_port = "Unknown"
            raw_data = b""

            if hasattr(pkt, 'tcp'):
                src_port = pkt.tcp.srcport
                dst_port = pkt.tcp.dstport
                if hasattr(pkt.tcp, 'payload'):
                    try:
                        raw_data = bytes.fromhex(pkt.tcp.payload.replace(":", ""))
                    except Exception:
                        pass
                # Extract native TCP fields
                seq = int(getattr(pkt.tcp, 'seq', 0))
                ack = int(getattr(pkt.tcp, 'ack', 0))
                win = int(getattr(pkt.tcp, 'window_size_value', 0))
                flags = int(getattr(pkt.tcp, 'flags_tree', 0) or 0)
                simulated = parse_simulated_tcp(raw_data)
                if simulated:
                    seq, ack, flags, win = simulated["seq"], simulated["ack"], simulated["flags"], simulated["window"]
                    csum = simulated["checksum"]
                    payload_len = simulated["data_len"]
                    payload_bytes = simulated["data"]
                else:
                    csum = int(getattr(pkt.tcp, 'checksum', 0), 16) if hasattr(pkt.tcp, 'checksum') else 0
                    payload_len = len(raw_data)
                    payload_bytes = raw_data

            elif hasattr(pkt, 'udp'):
                src_port = pkt.udp.srcport
                dst_port = pkt.udp.dstport
                if hasattr(pkt.udp, 'payload'):
                    try:
                        raw_data = bytes.fromhex(pkt.udp.payload.replace(":", ""))
                    except Exception:
                        pass
                simulated = parse_simulated_tcp(raw_data)
                if not simulated:
                    continue
                seq = simulated["seq"]
                ack = simulated["ack"]
                flags = simulated["flags"]
                win = simulated["window"]
                csum = simulated["checksum"]
                payload_len = simulated["data_len"]
                payload_bytes = simulated["data"]
            else:
                continue

            phase = determine_phase(flags, seq, stats["total"])
            if phase != current_phase:
                current_phase = phase
                print(f"\n{Colors.BOLD}{Colors.WHITE}━━━ [{current_phase}] ━━━{Colors.RESET}")

            # Check for retransmission
            is_retransmit = False
            if (flags & FLAG_DATA):
                if seq in seen_seqs:
                    is_retransmit = True
                    stats["retransmissions"] += 1
                else:
                    seen_seqs.add(seq)

            # Update stats
            if flags & FLAG_SYN:
                stats["handshake"] += 1
            if flags & FLAG_FIN:
                stats["termination"] += 1
            if flags & FLAG_DATA:
                stats["data"] += 1
            if (flags & FLAG_ACK) and not (flags & FLAG_DATA):
                stats["acks"] += 1
            if flags & FLAG_RST:
                stats["naks"] += 1

            # Determine status label & color
            flag_str = format_flags(flags)
            status_tag = ""
            tag_color = Colors.CYAN
            if is_retransmit:
                status_tag = " [⚠️ RETRANSMISSION]"
                tag_color = Colors.YELLOW
            elif flags & FLAG_RST:
                status_tag = " [❌ NAK/CHECKSUM ERROR]"
                tag_color = Colors.RED
            elif flags & FLAG_DATA:
                status_tag = f" [DATA Record #{seq}]"
                tag_color = Colors.BLUE
            elif flags & FLAG_ACK:
                status_tag = f" [ACK #{ack}]"
                tag_color = Colors.GREEN

            print(f"{tag_color}┌─ Packet #{stats['total']:03d} [{timestamp}] {src_port} → {dst_port}{status_tag}{Colors.RESET}")
            print(f"│  Seq: {seq:<8} Ack: {ack:<8} Flags: {flag_str:<16} Win: {win:<5} Checksum: 0x{csum:04X}")
            if payload_len > 0:
                print(f"│  Payload ({payload_len} bytes):")
                print(f"│  {Colors.YELLOW}{hex_dump(payload_bytes, 32)}{Colors.RESET}")
            print(f"{tag_color}└──────────────────────────────────────────────────────────────────────────{Colors.RESET}")

    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[INFO] Capture stopped by user.{Colors.RESET}")
    except Exception as e:
        print(f"\n{Colors.RED}[ERROR] Capture exception: {e}{Colors.RESET}")

    # Final Statistics Summary Dashboard
    print(f"\n{Colors.CYAN}{Colors.BOLD}")
    print("╔══════════════════════════════════════════════════════════════════╗")
    print("║               PACKET ANALYSIS & TRAFFIC SUMMARY                  ║")
    print("╠══════════════════════════════════════════════════════════════════╣")
    print(f"║  Total Packets Captured   : {stats['total']:<36} ║")
    print(f"║  Handshake Packets        : {stats['handshake']:<36} ║")
    print(f"║  Data Packets Transmitted : {stats['data']:<36} ║")
    print(f"║  Cumulative ACKs Received : {stats['acks']:<36} ║")
    print(f"║  Retransmissions Detected : {stats['retransmissions']:<36} ║")
    print(f"║  Negative ACKs (NAK/RST)  : {stats['naks']:<36} ║")
    print(f"║  Termination (FIN) Packets: {stats['termination']:<36} ║")
    print("╚══════════════════════════════════════════════════════════════════╝")
    print(f"{Colors.RESET}")

if __name__ == "__main__":
    main()
