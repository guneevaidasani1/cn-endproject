#ifndef TCP_COMMON_H
#define TCP_COMMON_H

#include <iostream>
#include <iomanip>
#include <string>
#include <sstream>
#include <vector>
#include <cstring>
#include <cstdint>
#include <cstdlib>
#include <cmath>
#include <chrono>

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #pragma comment(lib, "ws2_32.lib")
  typedef int socklen_t;
  #define close_socket closesocket
  #define sleep_ms(ms) Sleep(ms)
#else
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <unistd.h>
  #include <sys/select.h>
  #include <sys/time.h>
  #define close_socket close
  #define sleep_ms(ms) usleep((ms) * 1000)
#endif

// ============================================================================
// CONSTANTS & PROTOCOL FLAGS
// ============================================================================
constexpr int PORT = 9090;
constexpr int WINDOW_SIZE = 4;
constexpr int MAX_RECORDS = 20;

// TCP Flags representation (Bitmask)
constexpr uint8_t FLAG_SYN  = 0x01;  // Synchronize sequence numbers
constexpr uint8_t FLAG_ACK  = 0x02;  // Acknowledgment field valid
constexpr uint8_t FLAG_FIN  = 0x04;  // Finish connection teardown
constexpr uint8_t FLAG_DATA = 0x08;  // Payload contains application data
constexpr uint8_t FLAG_RST  = 0x10;  // Reset / Negative Acknowledgment (NAK)

// ============================================================================
// ANSI COLOR CODES FOR FORMATTED TERMINAL OUTPUT
// ============================================================================
namespace Color {
    const char* const RESET   = "\033[0m";
    const char* const BOLD    = "\033[1m";
    const char* const RED     = "\033[1;31m";
    const char* const GREEN   = "\033[1;32m";
    const char* const YELLOW  = "\033[1;33m";
    const char* const BLUE    = "\033[1;34m";
    const char* const MAGENTA = "\033[1;35m";
    const char* const CYAN    = "\033[1;36m";
    const char* const WHITE   = "\033[1;37m";
    const char* const BG_BLUE = "\033[44m";
}

// ============================================================================
// DATA STRUCTURES
// ============================================================================

// (b) Document Record Structure (Student Database Record)
#pragma pack(push, 1)
struct StudentRecord {
    int id;               // Student ID
    char name[32];        // Student Name
    char grade[8];        // Letter Grade (e.g., "A+", "B")
    float marks;          // Numerical Score (e.g., 95.5)
};

// Simulated TCP Packet Header & Payload
struct TCPPacket {
    uint32_t seq_num;     // Sequence number
    uint32_t ack_num;     // Acknowledgment number
    uint8_t  flags;       // TCP Flags (SYN, ACK, FIN, DATA, RST)
    uint16_t window_size; // Advertised receiver window size
    uint16_t checksum;    // 16-bit 1's complement Internet Checksum
    uint16_t data_len;    // Length of valid payload in data buffer
    char     data[256];   // Application data payload
};
#pragma pack(pop)

// ============================================================================
// (c) INTERNET CHECKSUM ALGORITHM (RFC 1071)
// 16-bit one's complement sum of all 16-bit words in the packet
// ============================================================================

inline uint16_t compute_checksum(const TCPPacket& pkt) {
    // Checksum is calculated with the checksum field initialized to zero
    TCPPacket temp = pkt;
    temp.checksum = 0;

    const uint8_t* buffer = reinterpret_cast<const uint8_t*>(&temp);
    size_t length = sizeof(TCPPacket);
    uint32_t sum = 0;

    // Sum all 16-bit words
    for (size_t i = 0; i < length - 1; i += 2) {
        uint16_t word = (static_cast<uint16_t>(buffer[i]) << 8) | static_cast<uint16_t>(buffer[i + 1]);
        sum += word;
    }

    // If packet has odd number of bytes, pad with zero byte
    if (length & 1) {
        sum += static_cast<uint16_t>(buffer[length - 1]) << 8;
    }

    // Fold 32-bit sum into 16 bits (carry addition)
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // One's complement
    return static_cast<uint16_t>(~sum);
}

inline bool verify_checksum(const TCPPacket& pkt) {
    uint16_t expected = compute_checksum(pkt);
    return pkt.checksum == expected;
}

// ============================================================================
// HELPER FORMATTING FUNCTIONS
// ============================================================================

inline std::string flags_to_string(uint8_t flags) {
    std::string s;
    if (flags & FLAG_SYN)  s += "SYN ";
    if (flags & FLAG_ACK)  s += "ACK ";
    if (flags & FLAG_FIN)  s += "FIN ";
    if (flags & FLAG_DATA) s += "DATA ";
    if (flags & FLAG_RST)  s += "RST/NAK ";
    if (s.empty()) s = "NONE";
    else if (s.back() == ' ') s.pop_back();
    return s;
}

// Pretty prints the TCP packet with ANSI box drawing characters
inline void print_packet(const TCPPacket& pkt, const std::string& direction, const std::string& note = "") {
    bool valid = verify_checksum(pkt);
    std::string flag_str = flags_to_string(pkt.flags);

    // Pick border color based on packet characteristics
    const char* border_color = Color::CYAN;
    if (!valid || (pkt.flags & FLAG_RST)) {
        border_color = Color::RED;
    } else if (pkt.flags & FLAG_ACK && !(pkt.flags & FLAG_DATA)) {
        border_color = Color::GREEN;
    } else if (pkt.flags & FLAG_DATA) {
        border_color = Color::BLUE;
    } else if (pkt.flags & (FLAG_SYN | FLAG_FIN)) {
        border_color = Color::CYAN;
    }

    std::cout << border_color;
    std::cout << "╔══════════════════════════════════════════════════════════╗\n";

    // Header row with direction and packet ID
    std::string title = " " + direction + " ";
    if (pkt.flags & FLAG_DATA) {
        title += "PACKET #" + std::to_string(pkt.seq_num) + " ";
    }
    title += "[" + flag_str + "]";
    if (!note.empty()) {
        title += " (" + note + ")";
    }

    std::cout << "║ " << std::left << std::setw(56) << title.substr(0, 56) << " ║\n";
    std::cout << "╠══════════════════════════════════════════════════════════╣\n";

    // Fields
    std::cout << "║  Seq Num    : " << std::left << std::setw(40) << pkt.seq_num << " ║\n";
    std::cout << "║  Ack Num    : " << std::left << std::setw(40) << pkt.ack_num << " ║\n";
    std::cout << "║  Flags      : " << std::left << std::setw(40) << flag_str << " ║\n";
    std::cout << "║  Window     : " << std::left << std::setw(40) << pkt.window_size << " ║\n";

    // Checksum with validation status
    std::stringstream cs_ss;
    cs_ss << "0x" << std::uppercase << std::hex << std::setw(4) << std::setfill('0') << pkt.checksum << std::dec;
    if (valid) {
        cs_ss << "  " << Color::GREEN << "[OK Valid]" << border_color;
    } else {
        cs_ss << "  " << Color::RED << "[CORRUPTED]" << border_color;
    }
    std::cout << "║  Checksum   : " << std::left << std::setw(49) << cs_ss.str() << " ║\n";

    // Data summary
    std::string data_summary;
    if (pkt.data_len >= sizeof(StudentRecord)) {
        StudentRecord rec;
        std::memcpy(&rec, pkt.data, sizeof(StudentRecord));
        std::stringstream rec_ss;
        rec_ss << "Record[" << rec.id << "] " << rec.name << " | Grade: " << rec.grade << " | Marks: " << std::fixed << std::setprecision(1) << rec.marks;
        data_summary = rec_ss.str();
    } else if (pkt.flags & FLAG_SYN) {
        data_summary = "(Connection Request Handshake)";
    } else if (pkt.flags & FLAG_FIN) {
        data_summary = "(Connection Teardown Request)";
    } else if (pkt.flags & FLAG_RST) {
        data_summary = "(Negative Acknowledgment - Corrupted Packet)";
    } else {
        data_summary = "(Control / Cumulative ACK)";
    }
    std::cout << "║  Data       : " << std::left << std::setw(40) << data_summary.substr(0, 40) << " ║\n";

    std::cout << "╚══════════════════════════════════════════════════════════╝\n";
    std::cout << Color::RESET << std::flush;
}

// (d) Sliding window visualizer
inline void print_window_state(int base, int next_seq, int win_size, int total_records) {
    int unacked = next_seq - base;
    if (unacked < 0) unacked = 0;
    int sent_in_win = std::min(unacked, win_size);

    std::cout << Color::MAGENTA << "[WINDOW] [";
    for (int i = 0; i < win_size; ++i) {
        if (i < sent_in_win) {
            std::cout << Color::YELLOW << "■ " << Color::MAGENTA;
        } else {
            std::cout << "□ ";
        }
    }
    std::cout << "] Sent: " << sent_in_win << "/" << win_size
              << "  Unacked: " << unacked
              << "  Base: " << base
              << "  NextSeq: " << next_seq
              << "  (Remaining: " << (total_records - base + 1 > 0 ? total_records - base + 1 : 0) << ")"
              << Color::RESET << "\n" << std::flush;
}

// (e) AIMD Congestion Control visualizer
inline void print_aimd_state(double cwnd, int ssthresh, const std::string& event, const std::string& action) {
    std::cout << Color::MAGENTA << Color::BOLD
              << "[CONGESTION] cwnd=" << std::fixed << std::setprecision(1) << cwnd
              << " ssthresh=" << ssthresh
              << " → " << event
              << " → " << action
              << Color::RESET << "\n" << std::flush;
}

// (g) Jacobson/Karels RTT Estimation visualizer
inline void print_rtt_state(double sample_ms, double srtt_ms, double rttvar_ms, double rto_ms) {
    std::cout << Color::CYAN
              << "[RTT] Sample=" << std::fixed << std::setprecision(1) << sample_ms << "ms  "
              << "SRTT=" << srtt_ms << "ms  "
              << "RTTVAR=" << rttvar_ms << "ms  "
              << "RTO=" << rto_ms << "ms"
              << Color::RESET << "\n" << std::flush;
}

#endif // TCP_COMMON_H
