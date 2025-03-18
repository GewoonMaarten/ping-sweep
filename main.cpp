#include <arpa/inet.h>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <mutex>
#include <ostream>
#include <sys/socket.h>
#include <thread>
#include <unordered_map>

using namespace std::chrono_literals;

class IcmpHeader {
private:
  uint8_t type{8};
  uint8_t code{0};
  uint16_t checksum{0};
  uint16_t identifier{0};
  uint16_t sequence_number{0};

  uint16_t calc_checksum() const {
    uint32_t sum = 0;

    sum += (type << 8) + code;
    sum += ntohs(identifier);
    sum += ntohs(sequence_number);

    return htons(static_cast<uint16_t>(~sum));
  }

  bool is_correct_checksum() const {
    uint32_t sum = 0;

    sum += (type << 8) + code;
    sum += ntohs(identifier);
    sum += ntohs(sequence_number);
    sum += ntohs(checksum);

    return sum == 0xFFFF;
  }

public:
  IcmpHeader() {}

  // Constructor to create an ICMP header from individual fields
  // Used for creating request packets for functions like `sendto`
  IcmpHeader(const uint16_t t_identifier, const uint16_t t_sequence_number)
      : identifier(htons(t_identifier)),
        sequence_number(htons(t_sequence_number)) {
    checksum = calc_checksum();
  }

  // Constructor to create an ICMP header from a buffer
  // Used for creating response packets from functions like `recvfrom`
  IcmpHeader(const uint8_t *buffer, size_t buffer_size) {
    if (buffer_size < sizeof(IcmpHeader)) {
      throw std::invalid_argument(
          "Buffer size is too small to construct IcmpHeader");
    }

    type = buffer[0];
    code = buffer[1];
    checksum = htons(*reinterpret_cast<const uint16_t *>(buffer + 2));
    identifier = htons(*reinterpret_cast<const uint16_t *>(buffer + 4));
    sequence_number = htons(*reinterpret_cast<const uint16_t *>(buffer + 6));

    // if (!is_correct_checksum())
    // {
    //     throw std::runtime_error("Invalid checksum in ICMP header");
    // }
  }

  void set_sequence_number(uint8_t t_sequence_number) {
    sequence_number = t_sequence_number;
    calc_checksum();
  }

  // Get identifier in host byte order
  uint16_t get_identifier() const { return identifier; }
  // Get sequence_number in host byte order
  uint16_t get_sequence_number() const { return sequence_number; }

  const uint8_t *data() const {
    return reinterpret_cast<const uint8_t *>(this);
  }

  size_t size() const { return sizeof(IcmpHeader); }
};

class SockAddr {
private:
  struct sockaddr_in addr{};

public:
  SockAddr() {}

  // Constructor with an IP string
  SockAddr(const std::string &ip, uint16_t port) {
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (inet_pton(AF_INET, ip.c_str(), &(addr.sin_addr)) != 1) {
      throw std::invalid_argument("Invalid IP address: " + ip);
    }
  }

  // Constructor with a 32-bit number for the IP
  SockAddr(in_addr_t ip, uint16_t port) {
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(ip);
  }

  // Method to retrieve the `sockaddr_in` object
  const sockaddr_in &get_sockaddr() const { return addr; }
};

class MessageHeader {
private:
public:
  SockAddr sock_addr;
  IcmpHeader icmp_header;

  MessageHeader() {}
  MessageHeader(const SockAddr &t_sock_addr, const IcmpHeader &t_icmp_header)
      : sock_addr(t_sock_addr), icmp_header(t_icmp_header) {}

  msghdr to_native() {
    msghdr inner{};
    inner.msg_name = (void *)&sock_addr.get_sockaddr();
    inner.msg_namelen = sizeof(sockaddr_in);

    iovec iov;
    iov.iov_base =
        const_cast<void *>(static_cast<const void *>(icmp_header.data()));
    iov.iov_len = icmp_header.size();
    inner.msg_iov = &iov;
    inner.msg_iovlen = 1;

    return inner;
  }

  static MessageHeader from_native(const msghdr &hdr) {
    if (!hdr.msg_name || hdr.msg_namelen != sizeof(sockaddr_in)) {
      throw std::invalid_argument("Invalid or missing address in msghdr");
    }

    const sockaddr_in *addr = static_cast<const sockaddr_in *>(hdr.msg_name);
    SockAddr sock_addr(ntohl(addr->sin_addr.s_addr), ntohs(addr->sin_port));

    if (!hdr.msg_iov || hdr.msg_iovlen != 1 || !hdr.msg_iov[0].iov_base) {
      throw std::invalid_argument("Invalid or missing iovec in msghdr");
    }

    const uint8_t *base_ptr =
        static_cast<const uint8_t *>(hdr.msg_iov[0].iov_base);
    const uint8_t *icmp_data = base_ptr + 20;
    size_t icmp_size = hdr.msg_iov[0].iov_len - 20;
    IcmpHeader icmp_header(icmp_data, icmp_size);

    MessageHeader message(sock_addr, icmp_header);
    return message;
  }
};

struct RequestInfo {
  std::chrono::steady_clock::time_point send_time;
  uint32_t ip;
  int retries;
};

class ThreadSafeMap {
private:
  std::unordered_map<uint32_t, RequestInfo> map;
  std::mutex mtx;

public:
  void add(uint32_t ip, std::chrono::steady_clock::time_point send_time) {
    std::lock_guard<std::mutex> lock(mtx);
    map[ip] = {send_time, ip, 0};
  }

  bool remove(uint32_t ip) {
    std::lock_guard<std::mutex> lock(mtx);
    return map.erase(ip) > 0;
  }

  void check_timeouts(std::chrono::seconds timeout_duration,
                      const int max_retries) {
    std::lock_guard<std::mutex> lock(mtx);
    auto now = std::chrono::steady_clock::now();

    for (auto it = map.begin(); it != map.end();) {
      if (now - it->second.send_time > timeout_duration) {
        if (it->second.retries >= max_retries) {
          std::cout << "Max retries reached for IP: " << it->second.ip
                    << std::endl;
          it = map.erase(it);
        } else {
          // Increment retry count and update send time
          it->second.retries++;
          it->second.send_time = now;
          std::cout << "Retrying to IP: " << it->second.ip << " (retry "
                    << it->second.retries << ")" << std::endl;
          ++it;
        }
      } else {
        ++it;
      }
    }
  }

  size_t get_size() { return map.size(); }
};

void sender_thread(int socket_fd, ThreadSafeMap &requests) {
  const size_t BATCH_SIZE = 1024;
  const std::chrono::milliseconds BATCH_DELAY(10); // Delay between batches
  const int MAX_RETRIES = 3;

  uint32_t current_ip = 134744072;
  while (current_ip <= UINT32_MAX) {
    struct mmsghdr messages[BATCH_SIZE];
    IcmpHeader icmp_headers[BATCH_SIZE];
    SockAddr sock_addrs[BATCH_SIZE];
    MessageHeader message_headers[BATCH_SIZE];

    uint32_t messages_in_batch = 0;
    for (; messages_in_batch < BATCH_SIZE && current_ip <= UINT32_MAX;
         messages_in_batch++) {
      icmp_headers[messages_in_batch] = IcmpHeader{0x1234, 0};
      sock_addrs[messages_in_batch] = SockAddr{current_ip, 0};
      message_headers[messages_in_batch] = MessageHeader{
          sock_addrs[messages_in_batch], icmp_headers[messages_in_batch]};

      messages[messages_in_batch].msg_hdr =
          message_headers[messages_in_batch].to_native();
      messages[messages_in_batch].msg_len = 0;

      current_ip++;
    }

    int retries = 0;
    while (retries < MAX_RETRIES) {
      int sent = sendmmsg(socket_fd, messages, messages_in_batch, 0);
      if (sent < 0) {
        if (errno == ENOBUFS || errno == EAGAIN || errno == EWOULDBLOCK) {
          retries++;
          std::this_thread::sleep_for(std::chrono::milliseconds(100));
          continue;
        }
        perror("sendmmsg");
        break;
      }

      for (int i = 0; i < sent; i++) {
        if (messages[i].msg_len > 0) {
          requests.add(sock_addrs[i].get_sockaddr().sin_addr.s_addr,
                       std::chrono::steady_clock::now());
        }
      }

      if (sent < messages_in_batch) {
        messages_in_batch -= sent;
        memmove(messages, messages + sent, messages_in_batch * sizeof(mmsghdr));
        retries++;
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
      } else {
        break;
      }
    }

    // Add delay between batches
    std::this_thread::sleep_for(BATCH_DELAY);

    if (current_ip >= UINT32_MAX)
      break;
  }
}

void receiver_thread(int socket_fd, ThreadSafeMap &requests) {
  while (true) {
    struct msghdr response_msghdr;
    struct iovec iov[1];
    struct sockaddr_in sin;
    response_msghdr.msg_name = &sin;
    response_msghdr.msg_namelen = sizeof(sin);
    response_msghdr.msg_iov = iov;
    response_msghdr.msg_iovlen = 1;

    char databuf[28];
    iov[0].iov_base = databuf;
    iov[0].iov_len = sizeof(databuf);
    memset(databuf, 0, sizeof(databuf));

    ssize_t received_bytes = recvmsg(socket_fd, &response_msghdr, 0);
    if (received_bytes < 0) {
      perror("recvmsg");
      continue;
    }

    try {
      MessageHeader response_message_header =
          MessageHeader::from_native(response_msghdr);
      uint32_t ip =
          response_message_header.sock_addr.get_sockaddr().sin_addr.s_addr;
      if (requests.remove(ip)) {
        std::cout << "Received and removed response for IP: " << ip
                  << std::endl;
      } else {
        std::cout << "No matching request found for IP: " << ip << std::endl;
      }

    } catch (const std::exception &e) {
      std::cerr << "Error processing response: " << e.what() << std::endl;
    }

    if (requests.get_size() == 0) {
      break;
    }
  }
}

int main() {
  std::cout << "Starting program..." << std::endl;

  int socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (socket_fd == -1) {
    perror("socket");
    return 1;
  }

  ThreadSafeMap requests;
  std::thread sender(sender_thread, socket_fd, std::ref(requests));
  std::thread receiver(receiver_thread, socket_fd, std::ref(requests));

  // Periodically check for timeouts
  // while (true) {
  //     requests.check_timeouts(5s, 3); // Adjust timeout duration as needed
  //     std::this_thread::sleep_for(5s);
  //     if (requests.get_size() == 0)
  //     {
  //         break;
  //     }
  // }

  sender.join();
  receiver.join();

  // close(socket_fd);
  std::cout << "Finished" << std::endl;
  return 0;
}
