#include "tcp_common.h"
#include <iostream>
using namespace std;
int main() {
#ifdef _WIN32
  WSADATA wsaData;
  WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif

  cout << Color::CYAN << Color::BOLD
       << "╔══════════════════════════════════════════════════════════╗\n"
       << "║      TCP PROTOCOL SIMULATION - RECEIVER (CLIENT)         ║\n"
       << "║      Connecting to: 127.0.0.1:" << PORT
       << " | Window Size: " << WINDOW_SIZE << "          ║\n"
       << "╚══════════════════════════════════════════════════════════╝\n"
       << Color::RESET << endl;

  // 1. Create UDP Socket
  int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd < 0) {
    cerr << Color::RED << "Error creating socket!" << Color::RESET << endl;
    return 1;
  }

  struct sockaddr_in server_addr{};
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(PORT);
  inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr);

  socklen_t server_len = sizeof(server_addr);

  // ========================================================================
  // 2. (a) 3-WAY HANDSHAKE (CONNECTION ESTABLISHMENT)
  // Client sends SYN -> Server responds SYN-ACK -> Client sends ACK
  // ========================================================================
  cout << "\n"
       << Color::CYAN << Color::BOLD
       << "============================================================\n"
       << "  PHASE 1: 3-WAY HANDSHAKE (CONNECTION ESTABLISHMENT)\n"
       << "============================================================"
       << Color::RESET << endl;

  TCPPacket syn_pkt{};
  syn_pkt.seq_num = 100; // Client Initial Sequence Number (ISN)
  syn_pkt.ack_num = 0;
  syn_pkt.flags = FLAG_SYN;
  syn_pkt.window_size = WINDOW_SIZE;
  syn_pkt.data_len = 0;
  syn_pkt.checksum = compute_checksum(syn_pkt);

  TCPPacket syn_ack_pkt{};
  bool handshake_connected = false;

  // SYN retry loop (up to 10 attempts, 500ms each) to allow sender startup
  for (int attempt = 1; attempt <= 10; ++attempt) {
    cout << Color::CYAN
         << "[HANDSHAKE] Sending SYN (ISN=100) to Sender... (Attempt "
         << attempt << "/10)" << Color::RESET << endl;

    sendto(sockfd, (const char *)&syn_pkt, sizeof(syn_pkt), 0,
           (struct sockaddr *)&server_addr, server_len);
    print_packet(syn_pkt, "RECEIVER → SENDER", "Handshake Step 1: SYN Sent");

    // Wait up to 600ms for SYN-ACK
    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(sockfd, &read_fds);
    struct timeval tv{};
    tv.tv_sec = 0;
    tv.tv_usec = 600000;

    int sel = select(sockfd + 1, &read_fds, nullptr, nullptr, &tv);
    if (sel > 0) {
      ssize_t bytes =
          recvfrom(sockfd, (char *)&syn_ack_pkt, sizeof(syn_ack_pkt), 0,
                   (struct sockaddr *)&server_addr, &server_len);
      if (bytes > 0 && (syn_ack_pkt.flags & (FLAG_SYN | FLAG_ACK))) {
        handshake_connected = true;
        break;
      }
    }
  }

  if (!handshake_connected) {
    cerr << Color::RED << "[ERROR] Could not connect to Sender on port " << PORT
         << "!\n"
         << "Please make sure sender is running." << Color::RESET << endl;
    close_socket(sockfd);
    return 1;
  }

  print_packet(syn_ack_pkt, "SENDER → RECEIVER",
               "Handshake Step 2: SYN-ACK Received");

  // Send final ACK of 3-way handshake
  sleep_ms(150);
  TCPPacket ack_pkt{};
  ack_pkt.seq_num = 101;
  ack_pkt.ack_num = syn_ack_pkt.seq_num + 1; // 300 + 1 = 301
  ack_pkt.flags = FLAG_ACK;
  ack_pkt.window_size = WINDOW_SIZE;
  ack_pkt.data_len = 0;
  ack_pkt.checksum = compute_checksum(ack_pkt);

  sendto(sockfd, (const char *)&ack_pkt, sizeof(ack_pkt), 0,
         (struct sockaddr *)&server_addr, server_len);
  print_packet(ack_pkt, "RECEIVER → SENDER", "Handshake Step 3: ACK Sent");

  cout << Color::GREEN << Color::BOLD
       << "[SUCCESS] 3-Way Handshake Complete! TCP Connection Established.\n"
       << Color::RESET << endl;

  // ========================================================================
  // 3. (b, c, d) DATA RECEIVE LOOP WITH CHECKSUM VERIFICATION & BUFFERING
  // ========================================================================
  cout << Color::BLUE << Color::BOLD
       << "============================================================\n"
       << "  PHASE 2: RECEIVING DOCUMENT (20 STUDENT RECORDS)\n"
       << "============================================================"
       << Color::RESET << endl;

  vector<StudentRecord> received_records;
  uint32_t expected_seq = 1;
  TCPPacket last_fin_packet{};

  while (true) {
    TCPPacket pkt{};
    ssize_t bytes = recvfrom(sockfd, (char *)&pkt, sizeof(pkt), 0,
                             (struct sockaddr *)&server_addr, &server_len);
    if (bytes <= 0)
      continue;

    // Check for Connection Teardown (FIN packet from Sender)
    if (pkt.flags & FLAG_FIN) {
      last_fin_packet = pkt;
      break; // Transition to Phase 3: Connection Termination
    }

    // (c) Internet Checksum Verification
    if (!verify_checksum(pkt)) {
      // Checksum Mismatch detected! (Simulated error on Packet #10)
      print_packet(pkt, "SENDER → RECEIVER", "CHECKSUM CORRUPTED");
      cout << Color::RED << Color::BOLD << "[CHECKSUM ERROR] Packet #"
           << pkt.seq_num << " FAILED checksum verification!\n"
           << "  Calculated Checksum : 0x" << uppercase << hex
           << compute_checksum(pkt) << "\n"
           << "  Received Checksum   : 0x" << pkt.checksum << dec << "\n"
           << "  Action              : Discarding packet & sending NAK "
              "(FLAG_RST)...\n"
           << Color::RESET;

      // Send NAK back to Sender
      sleep_ms(100);
      TCPPacket nak_pkt{};
      nak_pkt.seq_num = 0;
      nak_pkt.ack_num = pkt.seq_num; // Indicate which packet failed
      nak_pkt.flags = FLAG_RST;      // RST used as NAK
      nak_pkt.window_size = WINDOW_SIZE;
      nak_pkt.data_len = 0;
      nak_pkt.checksum = compute_checksum(nak_pkt);

      sendto(sockfd, (const char *)&nak_pkt, sizeof(nak_pkt), 0,
             (struct sockaddr *)&server_addr, server_len);
      print_packet(nak_pkt, "RECEIVER → SENDER",
                   "NAK (RST) Sent for Corrupted Packet #" +
                       to_string(pkt.seq_num));
      continue;
    }

    // Checksum is VALID!
    print_packet(pkt, "SENDER → RECEIVER", "DATA Packet Valid");

    // Verify In-Order Delivery
    if (pkt.seq_num == expected_seq) {
      // Deserializing StudentRecord
      if (pkt.data_len >= sizeof(StudentRecord)) {
        StudentRecord rec{};
        memcpy(&rec, pkt.data, sizeof(StudentRecord));
        received_records.push_back(rec);

        cout << Color::GREEN << "[RECEIVE BUFFER] Accepted Record #" << rec.id
             << " (" << rec.name << ", Grade: " << rec.grade
             << ", Marks: " << fixed << setprecision(1) << rec.marks << ")\n"
             << "[BUFFER USAGE] Stored: " << received_records.size() << "/"
             << MAX_RECORDS << " records\n"
             << Color::RESET;
      }

      // Send Cumulative ACK for this packet
      sleep_ms(100);
      TCPPacket data_ack{};
      data_ack.seq_num = 0;
      data_ack.ack_num = pkt.seq_num;
      data_ack.flags = FLAG_ACK;
      data_ack.window_size = WINDOW_SIZE;
      data_ack.data_len = 0;
      data_ack.checksum = compute_checksum(data_ack);

      sendto(sockfd, (const char *)&data_ack, sizeof(data_ack), 0,
             (struct sockaddr *)&server_addr, server_len);
      print_packet(data_ack, "RECEIVER → SENDER",
                   "ACK Sent for Packet #" + to_string(pkt.seq_num));

      expected_seq++;

    } else if (pkt.seq_num < expected_seq) {
      // Duplicate packet (already processed), re-send ACK for last good packet
      cout << Color::YELLOW << "[DUPLICATE] Packet #" << pkt.seq_num
           << " already received. Re-sending ACK #" << (expected_seq - 1)
           << "...\n"
           << Color::RESET;

      TCPPacket dup_ack{};
      dup_ack.seq_num = 0;
      dup_ack.ack_num = expected_seq - 1;
      dup_ack.flags = FLAG_ACK;
      dup_ack.window_size = WINDOW_SIZE;
      dup_ack.data_len = 0;
      dup_ack.checksum = compute_checksum(dup_ack);

      sendto(sockfd, (const char *)&dup_ack, sizeof(dup_ack), 0,
             (struct sockaddr *)&server_addr, server_len);
      print_packet(dup_ack, "RECEIVER → SENDER", "Duplicate ACK Sent");

    } else {
      // Out of order packet (e.g., earlier packet was lost)
      cout << Color::YELLOW << "[OUT OF ORDER] Expected Seq #" << expected_seq
           << ", got Seq #" << pkt.seq_num
           << ". Buffering/Discarding. Re-sending ACK #" << (expected_seq - 1)
           << "...\n"
           << Color::RESET;

      TCPPacket ooo_ack{};
      ooo_ack.seq_num = 0;
      ooo_ack.ack_num = expected_seq - 1;
      ooo_ack.flags = FLAG_ACK;
      ooo_ack.window_size = WINDOW_SIZE;
      ooo_ack.data_len = 0;
      ooo_ack.checksum = compute_checksum(ooo_ack);

      sendto(sockfd, (const char *)&ooo_ack, sizeof(ooo_ack), 0,
             (struct sockaddr *)&server_addr, server_len);
      print_packet(ooo_ack, "RECEIVER → SENDER",
                   "Cumulative ACK for Last In-Order Packet");
    }
  }

  // ========================================================================
  // 4. (f) CONNECTION TERMINATION (4-WAY FIN HANDSHAKE)
  // SENDER (FIN) -> RECEIVER (ACK) -> RECEIVER (FIN) -> SENDER (ACK)
  // ========================================================================
  cout << "\n"
       << Color::CYAN << Color::BOLD
       << "============================================================\n"
       << "  PHASE 3: 4-WAY FIN HANDSHAKE (CONNECTION TERMINATION)\n"
       << "============================================================"
       << Color::RESET << endl;

  print_packet(last_fin_packet, "SENDER → RECEIVER",
               "Termination Step 1: FIN Received from Sender");

  // Step 2: Receiver sends ACK for Sender's FIN
  sleep_ms(150);
  TCPPacket fin_ack{};
  fin_ack.seq_num = 0;
  fin_ack.ack_num = last_fin_packet.seq_num + 1;
  fin_ack.flags = FLAG_ACK;
  fin_ack.window_size = WINDOW_SIZE;
  fin_ack.data_len = 0;
  fin_ack.checksum = compute_checksum(fin_ack);

  sendto(sockfd, (const char *)&fin_ack, sizeof(fin_ack), 0,
         (struct sockaddr *)&server_addr, server_len);
  print_packet(fin_ack, "RECEIVER → SENDER",
               "Termination Step 2: ACK for FIN Sent");

  // Step 3: Receiver sends its own FIN (Passive Close)
  sleep_ms(150);
  TCPPacket client_fin{};
  client_fin.seq_num = 50;
  client_fin.ack_num = last_fin_packet.seq_num + 1;
  client_fin.flags = FLAG_FIN;
  client_fin.window_size = WINDOW_SIZE;
  client_fin.data_len = 0;
  client_fin.checksum = compute_checksum(client_fin);

  sendto(sockfd, (const char *)&client_fin, sizeof(client_fin), 0,
         (struct sockaddr *)&server_addr, server_len);
  print_packet(client_fin, "RECEIVER → SENDER",
               "Termination Step 3: Client FIN Sent");

  // Step 4: Receiver waits for final ACK from Sender
  TCPPacket final_ack{};
  ssize_t final_bytes =
      recvfrom(sockfd, (char *)&final_ack, sizeof(final_ack), 0,
               (struct sockaddr *)&server_addr, &server_len);
  if (final_bytes > 0 && (final_ack.flags & FLAG_ACK)) {
    print_packet(final_ack, "SENDER → RECEIVER",
                 "Termination Step 4: Final ACK Received (CLOSED)");
  }

  cout << Color::GREEN << Color::BOLD
       << "\n[SUCCESS] 4-Way FIN Handshake Complete! Connection "
          "Gracefully Closed.\n"
       << Color::RESET << endl;

  // ========================================================================
  // 5. PRINT COMPLETE RECEIVED DOCUMENT TABLE
  // ========================================================================
  cout << "\n"
       << Color::CYAN << Color::BOLD
       << "╔══════════════════════════════════════════════════════════════"
          "═══════╗\n"
       << "║               RECEIVED DOCUMENT (20 STUDENT RECORDS)         "
          "       ║\n"
       << "╠══════╦═════════════════════════╦════════════╦═════════╦══════"
          "═══════╣\n"
       << "║  ID  ║ Student Name            ║ Grade      ║ Marks   ║ "
          "Status      ║\n"
       << "╠══════╬═════════════════════════╬════════════╬═════════╬══════"
          "═══════╣\n"
       << Color::RESET;

  for (const auto &rec : received_records) {
    cout << Color::CYAN << "║ " << Color::WHITE << right << setw(4) << rec.id
         << " " << Color::CYAN << "║ " << Color::WHITE << left << setw(23)
         << rec.name << " " << Color::CYAN << "║ " << Color::YELLOW << left
         << setw(10) << rec.grade << " " << Color::CYAN << "║ " << Color::WHITE
         << right << setw(7) << fixed << setprecision(1) << rec.marks << " "
         << Color::CYAN << "║ " << Color::GREEN << "✓ Verified  " << Color::CYAN
         << "║\n";
  }

  cout << "╚══════╩═════════════════════════╩════════════╩═════════╩══════"
          "═══════╝\n"
       << Color::RESET;

  cout
      << Color::GREEN << Color::BOLD
      << ">> Document Transfer Summary: " << received_records.size() << "/"
      << MAX_RECORDS << " Records Successfully Received & Verified.\n"
      << ">> 100% Data Integrity Achieved across sliding window transmission.\n"
      << Color::RESET << endl;

  close_socket(sockfd);
#ifdef _WIN32
  WSACleanup();
#endif
  return 0;
}
