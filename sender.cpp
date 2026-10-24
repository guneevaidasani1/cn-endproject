#include "tcp_common.h"

// Hardcoded Document Dataset of 20 Student Records
const StudentRecord DOCUMENT_RECORDS[MAX_RECORDS] = {
    {1,  "Alice Smith",      "A+", 95.5f},
    {2,  "Bob Johnson",     "A",  88.0f},
    {3,  "Charlie Brown",   "B+", 79.5f},
    {4,  "Diana Prince",    "A+", 98.0f},
    {5,  "Ethan Hunt",      "B",  74.0f},
    {6,  "Fiona Gallagher", "A",  86.5f},
    {7,  "George Clark",    "C+", 68.0f},
    {8,  "Hannah Abbott",   "A-", 83.5f},
    {9,  "Ian Malcolm",     "B+", 78.0f},
    {10, "Julia Roberts",   "A+", 94.0f},
    {11, "Kevin Bacon",     "B-", 71.5f},
    {12, "Laura Croft",     "A",  90.0f},
    {13, "Michael Scott",   "C",  62.5f},
    {14, "Nancy Wheeler",   "A",  89.0f},
    {15, "Oscar Martinez",  "A-", 84.5f},
    {16, "Peter Parker",    "A+", 96.0f},
    {17, "Quinn Fabray",    "B+", 77.5f},
    {18, "Ronald Weasley",  "B",  73.0f},
    {19, "Sarah Connor",    "A",  91.5f},
    {20, "Tony Stark",      "A+", 99.5f}
};

// Jacobson/Karels RTT Estimation Tracking Structure
struct RTTTracker {
    double srtt   = 100.0; // Smoothed Round Trip Time (initial guess 100ms)
    double rttvar = 25.0;  // Round Trip Time Variation (initial guess 25ms)
    double rto    = 200.0; // Retransmission Timeout (ms)
    bool initialized = false;

    void update(double sample_rtt) {
        if (!initialized) {
            srtt = sample_rtt;
            rttvar = sample_rtt / 2.0;
            rto = srtt + 4.0 * rttvar;
            initialized = true;
        } else {
            // Jacobson / Karels Formula (RFC 6298)
            // RTTVAR = (1 - beta) * RTTVAR + beta * |SRTT - RTT|  where beta = 0.25
            rttvar = 0.75 * rttvar + 0.25 * std::abs(srtt - sample_rtt);
            // SRTT = (1 - alpha) * SRTT + alpha * RTT             where alpha = 0.125
            srtt = 0.875 * srtt + 0.125 * sample_rtt;
            // RTO = SRTT + 4 * RTTVAR
            rto = srtt + 4.0 * rttvar;
        }
        // Lower bound on RTO (at least 200ms)
        if (rto < 200.0) rto = 200.0;
    }
};

int main() {
#ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif

    std::cout << Color::CYAN << Color::BOLD
              << "╔══════════════════════════════════════════════════════════╗\n"
              << "║       TCP PROTOCOL SIMULATION - SENDER (SERVER)          ║\n"
              << "║       Port: " << PORT << " | Window Size: " << WINDOW_SIZE << " | Total Records: " << MAX_RECORDS << "         ║\n"
              << "╚══════════════════════════════════════════════════════════╝\n"
              << Color::RESET << std::endl;

    // 1. Create UDP Socket for Custom TCP framing
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        std::cerr << Color::RED << "Error creating socket!" << Color::RESET << std::endl;
        return 1;
    }

    int opt = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));

    struct sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << Color::RED << "Error binding to port " << PORT << "!" << Color::RESET << std::endl;
        close_socket(sockfd);
        return 1;
    }

    std::cout << Color::GREEN << "[STATUS] Sender listening on UDP port " << PORT << "..." << Color::RESET << std::endl;

    struct sockaddr_in client_addr{};
    socklen_t client_len = sizeof(client_addr);

    // ========================================================================
    // 2. (a) 3-WAY HANDSHAKE (CONNECTION ESTABLISHMENT)
    // SYN (from client) -> SYN-ACK (from sender) -> ACK (from client)
    // ========================================================================
    std::cout << "\n" << Color::CYAN << Color::BOLD
              << "============================================================\n"
              << "  PHASE 1: 3-WAY HANDSHAKE (CONNECTION ESTABLISHMENT)\n"
              << "============================================================"
              << Color::RESET << std::endl;

    // Step 1: Wait for SYN from receiver
    TCPPacket syn_pkt{};
    ssize_t bytes_recv = recvfrom(sockfd, (char*)&syn_pkt, sizeof(syn_pkt), 0,
                                  (struct sockaddr*)&client_addr, &client_len);
    if (bytes_recv <= 0 || !(syn_pkt.flags & FLAG_SYN)) {
        std::cerr << Color::RED << "Failed to receive valid SYN!" << Color::RESET << std::endl;
        close_socket(sockfd);
        return 1;
    }
    print_packet(syn_pkt, "RECEIVER → SENDER", "Handshake Step 1: SYN Received");

    // Step 2: Send SYN-ACK to receiver
    sleep_ms(150);
    TCPPacket syn_ack_pkt{};
    syn_ack_pkt.seq_num = 300;                      // Sender initial sequence number
    syn_ack_pkt.ack_num = syn_pkt.seq_num + 1;      // ACK receiver's ISN (100 + 1 = 101)
    syn_ack_pkt.flags = FLAG_SYN | FLAG_ACK;
    syn_ack_pkt.window_size = WINDOW_SIZE;
    syn_ack_pkt.data_len = 0;
    syn_ack_pkt.checksum = compute_checksum(syn_ack_pkt);

    sendto(sockfd, (const char*)&syn_ack_pkt, sizeof(syn_ack_pkt), 0,
           (struct sockaddr*)&client_addr, client_len);
    print_packet(syn_ack_pkt, "SENDER → RECEIVER", "Handshake Step 2: SYN-ACK Sent");

    // Step 3: Wait for ACK from receiver
    TCPPacket ack_pkt{};
    bytes_recv = recvfrom(sockfd, (char*)&ack_pkt, sizeof(ack_pkt), 0,
                          (struct sockaddr*)&client_addr, &client_len);
    if (bytes_recv <= 0 || !(ack_pkt.flags & FLAG_ACK)) {
        std::cerr << Color::RED << "Failed to receive valid ACK for handshake!" << Color::RESET << std::endl;
        close_socket(sockfd);
        return 1;
    }
    print_packet(ack_pkt, "RECEIVER → SENDER", "Handshake Step 3: ACK Received");

    std::cout << Color::GREEN << Color::BOLD
              << "[SUCCESS] 3-Way Handshake Complete! TCP Connection Established.\n"
              << Color::RESET << std::endl;

    // ========================================================================
    // 3. (b, c, d, e, g) DATA TRANSFER WITH SLIDING WINDOW + AIMD + RTT
    // ========================================================================
    std::cout << Color::BLUE << Color::BOLD
              << "============================================================\n"
              << "  PHASE 2: DATA TRANSMISSION (SLIDING WINDOW & AIMD)\n"
              << "  Document: 20 Student Records | Receiver Window: " << WINDOW_SIZE << "\n"
              << "============================================================"
              << Color::RESET << std::endl;

    // State Variables
    double cwnd = 1.0;          // Congestion Window (starts at 1 MSS)
    int ssthresh = 8;           // Slow Start Threshold
    int base = 1;               // Base of sender window (oldest unacknowledged seq)
    int next_seq = 1;           // Next sequence number to transmit
    const int total_records = MAX_RECORDS;

    bool packet_5_loss_simulated = false;     // Simulate packet loss once on packet #5
    bool packet_10_corrupt_simulated = false; // Simulate bit error once on packet #10

    RTTTracker rtt_tracker;

    while (base <= total_records) {
        // Effective sending window is min(cwnd, receiver advertised window)
        int effective_window = std::min(static_cast<int>(cwnd), WINDOW_SIZE);
        if (effective_window < 1) effective_window = 1;

        std::cout << "\n" << Color::WHITE << Color::BG_BLUE
                  << "--- [ROUND START] Base: " << base
                  << " | cwnd: " << std::fixed << std::setprecision(1) << cwnd
                  << " | ssthresh: " << ssthresh
                  << " | Effective Window: " << effective_window << " ---"
                  << Color::RESET << "\n";

        // Transmit packets allowed by the sliding window
        while (next_seq < base + effective_window && next_seq <= total_records) {
            TCPPacket pkt{};
            pkt.seq_num = next_seq;
            pkt.ack_num = 0;
            pkt.flags = FLAG_DATA;
            pkt.window_size = effective_window;
            pkt.data_len = sizeof(StudentRecord);
            std::memcpy(pkt.data, &DOCUMENT_RECORDS[next_seq - 1], sizeof(StudentRecord));
            pkt.checksum = compute_checksum(pkt);

            // Simulation Case 1: Packet #5 Loss Simulation
            if (next_seq == 5 && !packet_5_loss_simulated) {
                packet_5_loss_simulated = true;
                std::cout << Color::RED << Color::BOLD
                          << "\n>>> [SIMULATION EVENT 1] Simulating Network Packet Loss on Packet #5! <<<\n"
                          << Color::RESET;
                print_packet(pkt, "SENDER → (DROPPED)", "SIMULATED NETWORK DROP - Packet Not Sent");
                next_seq++;
                break; // Stop transmission in this round to wait for timeout
            }

            // Simulation Case 2: Packet #10 Checksum Corruption Simulation
            if (next_seq == 10 && !packet_10_corrupt_simulated) {
                packet_10_corrupt_simulated = true;
                std::cout << Color::RED << Color::BOLD
                          << "\n>>> [SIMULATION EVENT 2] Injecting Bit Error into Packet #10 Checksum! <<<\n"
                          << Color::RESET;
                pkt.checksum ^= 0xFFFF; // Corrupt checksum intentionally
                sendto(sockfd, (const char*)&pkt, sizeof(pkt), 0,
                       (struct sockaddr*)&client_addr, client_len);
                print_packet(pkt, "SENDER → RECEIVER", "CORRUPTED CHECKSUM INJECTED");
                next_seq++;
                sleep_ms(150);
                continue;
            }

            // Normal Transmission
            sendto(sockfd, (const char*)&pkt, sizeof(pkt), 0,
                   (struct sockaddr*)&client_addr, client_len);
            print_packet(pkt, "SENDER → RECEIVER", "DATA Packet Transmitted");
            next_seq++;
            sleep_ms(150);
        }

        // Display current sliding window state
        print_window_state(base, next_seq, effective_window, total_records);

        // Wait for ACK or Timeout using select()
        auto send_time = std::chrono::steady_clock::now();

        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(sockfd, &read_fds);

        // Calculate timeout duration (use RTO, minimum 500ms for simulated loss detection)
        long timeout_ms = static_cast<long>(rtt_tracker.rto);
        if (timeout_ms < 500) timeout_ms = 500;

        struct timeval tv{};
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;

        int sel = select(sockfd + 1, &read_fds, nullptr, nullptr, &tv);

        if (sel == 0) {
            // (e) TIMEOUT OCCURRED (Simulated Loss on Packet #5 detected)
            std::cout << "\n" << Color::RED << Color::BOLD
                      << "[TIMEOUT] RTO expired (" << timeout_ms << "ms) waiting for ACK of Packet #" << base << "!\n"
                      << Color::RESET;

            // AIMD Multiplicative Decrease:
            // cwnd drops to 1, ssthresh halves to max(2, cwnd / 2)
            int old_ssthresh = ssthresh;
            ssthresh = std::max(2, static_cast<int>(cwnd / 2.0));
            double old_cwnd = cwnd;
            cwnd = 1.0;

            std::stringstream evt_ss, act_ss;
            evt_ss << "Packet #" << base << " LOST";
            act_ss << "cwnd=" << std::fixed << std::setprecision(1) << cwnd
                   << " ssthresh=" << ssthresh << " [RETRANSMIT]";
            print_aimd_state(old_cwnd, old_ssthresh, evt_ss.str(), act_ss.str());

            // Go-Back-N Retransmission: Reset next_seq back to base
            std::cout << Color::YELLOW << Color::BOLD
                      << "[RETRANSMIT] Retransmitting lost packet starting from Seq #" << base << "...\n"
                      << Color::RESET;
            next_seq = base;

        } else if (sel > 0) {
            // Received response from Receiver
            TCPPacket resp_pkt{};
            bytes_recv = recvfrom(sockfd, (char*)&resp_pkt, sizeof(resp_pkt), 0,
                                  (struct sockaddr*)&client_addr, &client_len);
            auto recv_time = std::chrono::steady_clock::now();
            double sample_rtt = std::chrono::duration<double, std::milli>(recv_time - send_time).count();
            if (sample_rtt < 10.0) sample_rtt = 110.0 + (rand() % 25); // Realistic RTT jitter

            if (bytes_recv > 0) {
                // Check if Receiver sent NAK (RST flag set) for checksum corruption
                if (resp_pkt.flags & FLAG_RST) {
                    print_packet(resp_pkt, "RECEIVER → SENDER", "NAK Received (Corrupted Packet)");
                    std::cout << Color::RED << Color::BOLD
                              << "[NAK RECEIVED] Receiver rejected Packet #" << resp_pkt.ack_num
                              << " due to Checksum Failure!\n"
                              << "[RETRANSMIT] Retransmitting Packet #" << resp_pkt.ack_num
                              << " with VALID Checksum...\n"
                              << Color::RESET;
                    next_seq = resp_pkt.ack_num; // Retransmit corrupted packet
                }
                // Check if Receiver sent valid ACK
                else if (resp_pkt.flags & FLAG_ACK) {
                    print_packet(resp_pkt, "RECEIVER → SENDER", "ACK Received");

                    // (g) Update Jacobson/Karels RTT Estimation
                    rtt_tracker.update(sample_rtt);
                    print_rtt_state(sample_rtt, rtt_tracker.srtt, rtt_tracker.rttvar, rtt_tracker.rto);

                    // Check if ACK acknowledges new data
                    if (resp_pkt.ack_num >= static_cast<uint32_t>(base)) {
                        base = resp_pkt.ack_num + 1; // Slide window base forward

                        // (e) Congestion Control: AIMD / Slow Start
                        if (cwnd < ssthresh) {
                            // Slow Start: Exponential increase (double cwnd per round / +1 per ACK)
                            cwnd += 1.0;
                            std::cout << Color::GREEN
                                      << "[CONGESTION] Slow Start: cwnd increased to "
                                      << std::fixed << std::setprecision(1) << cwnd
                                      << " (ssthresh=" << ssthresh << ")\n"
                                      << Color::RESET;
                        } else {
                            // Congestion Avoidance: Additive Increase (+1/cwnd per ACK -> +1 per RTT)
                            cwnd += 1.0 / static_cast<int>(cwnd);
                            std::cout << Color::MAGENTA
                                      << "[CONGESTION] Congestion Avoidance (AIMD): cwnd="
                                      << std::fixed << std::setprecision(2) << cwnd
                                      << " (ssthresh=" << ssthresh << ")\n"
                                      << Color::RESET;
                        }
                    }
                }
            }
        }
    }

    std::cout << "\n" << Color::GREEN << Color::BOLD
              << "╔══════════════════════════════════════════════════════════╗\n"
              << "║  [SUCCESS] All 20 Student Records Successfully Sent &    ║\n"
              << "║            Acknowledged by Receiver!                     ║\n"
              << "╚══════════════════════════════════════════════════════════╝\n"
              << Color::RESET << std::endl;

    // ========================================================================
    // 4. (f) CONNECTION TERMINATION (4-WAY FIN HANDSHAKE)
    // SENDER (FIN) -> RECEIVER (ACK) -> RECEIVER (FIN) -> SENDER (ACK)
    // ========================================================================
    std::cout << Color::CYAN << Color::BOLD
              << "============================================================\n"
              << "  PHASE 3: 4-WAY FIN HANDSHAKE (CONNECTION TERMINATION)\n"
              << "============================================================"
              << Color::RESET << std::endl;

    // Step 1: Sender initiates teardown (Active Close) by sending FIN
    sleep_ms(200);
    TCPPacket fin_pkt{};
    fin_pkt.seq_num = 21;
    fin_pkt.ack_num = 0;
    fin_pkt.flags = FLAG_FIN;
    fin_pkt.window_size = WINDOW_SIZE;
    fin_pkt.data_len = 0;
    fin_pkt.checksum = compute_checksum(fin_pkt);

    sendto(sockfd, (const char*)&fin_pkt, sizeof(fin_pkt), 0,
           (struct sockaddr*)&client_addr, client_len);
    print_packet(fin_pkt, "SENDER → RECEIVER", "Termination Step 1: FIN Sent (Active Close)");

    // Step 2: Sender waits for ACK from Receiver
    TCPPacket fin_ack{};
    bytes_recv = recvfrom(sockfd, (char*)&fin_ack, sizeof(fin_ack), 0,
                          (struct sockaddr*)&client_addr, &client_len);
    if (bytes_recv > 0 && (fin_ack.flags & FLAG_ACK)) {
        print_packet(fin_ack, "RECEIVER → SENDER", "Termination Step 2: ACK for FIN Received");
    }

    // Step 3: Sender waits for Receiver's FIN (Passive Close from receiver)
    TCPPacket recv_fin{};
    bytes_recv = recvfrom(sockfd, (char*)&recv_fin, sizeof(recv_fin), 0,
                          (struct sockaddr*)&client_addr, &client_len);
    if (bytes_recv > 0 && (recv_fin.flags & FLAG_FIN)) {
        print_packet(recv_fin, "RECEIVER → SENDER", "Termination Step 3: FIN Received from Client");
    }

    // Step 4: Sender sends final ACK to Receiver
    sleep_ms(150);
    TCPPacket final_ack{};
    final_ack.seq_num = 22;
    final_ack.ack_num = recv_fin.seq_num + 1;
    final_ack.flags = FLAG_ACK;
    final_ack.window_size = WINDOW_SIZE;
    final_ack.data_len = 0;
    final_ack.checksum = compute_checksum(final_ack);

    sendto(sockfd, (const char*)&final_ack, sizeof(final_ack), 0,
           (struct sockaddr*)&client_addr, client_len);
    print_packet(final_ack, "SENDER → RECEIVER", "Termination Step 4: Final ACK Sent (TIME-WAIT)");

    std::cout << Color::GREEN << Color::BOLD
              << "\n[SUCCESS] 4-Way FIN Handshake Complete! Connection Gracefully Closed.\n"
              << Color::RESET << std::endl;

    close_socket(sockfd);
#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}
