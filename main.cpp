#include <arpa/inet.h>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <thread>
#include <mutex>
#include <unordered_map>
#include <condition_variable>


using namespace std::chrono_literals;

class IcmpHeader
{
private:
    uint8_t type{8};
    uint8_t code{0};
    uint16_t checksum{0};
    uint16_t identifier{0};
    uint16_t sequence_number{0};

    uint16_t calc_checksum() const
    {
        uint32_t sum = 0;

        sum += (type << 8) + code;
        sum += ntohs(identifier);
        sum += ntohs(sequence_number);

        return htons(static_cast<uint16_t>(~sum));
    }

    bool is_correct_checksum() const
    {
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
        : identifier(htons(t_identifier)), sequence_number(htons(t_sequence_number))
    {
        checksum = calc_checksum();
    }

    // Constructor to create an ICMP header from a buffer
    // Used for creating response packets from functions like `recvfrom`
    IcmpHeader(const uint8_t *buffer, size_t buffer_size)
    {
        if (buffer_size < sizeof(IcmpHeader))
        {
            throw std::invalid_argument("Buffer size is too small to construct IcmpHeader");
        }

        type = buffer[0];
        code = buffer[1];
        checksum = htons(*reinterpret_cast<const uint16_t *>(buffer + 2));
        identifier = htons(*reinterpret_cast<const uint16_t *>(buffer + 4));
        sequence_number = htons(*reinterpret_cast<const uint16_t *>(buffer + 6));

        if (!is_correct_checksum())
        {
            throw std::runtime_error("Invalid checksum in ICMP header");
        }
    }

    void set_sequence_number(uint8_t t_sequence_number)
    {
        sequence_number = t_sequence_number;
        calc_checksum();
    }

    // Get identifier in host byte order
    uint16_t get_identifier() const { return identifier; }
    // Get sequence_number in host byte order
    uint16_t get_sequence_number() const { return sequence_number; }

    const uint8_t *data() const
    {
        return reinterpret_cast<const uint8_t *>(this);
    }

    size_t size() const
    {
        return sizeof(IcmpHeader);
    }
};

class SockAddr
{
private:
    struct sockaddr_in addr
    {
    };

public:
    SockAddr() {}

    // Constructor with an IP string
    SockAddr(const std::string &ip, uint16_t port)
    {
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);

        if (inet_pton(AF_INET, ip.c_str(), &(addr.sin_addr)) != 1)
        {
            throw std::invalid_argument("Invalid IP address: " + ip);
        }
    }

    // Constructor with a 32-bit number for the IP
    SockAddr(in_addr_t ip, uint16_t port)
    {
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = htonl(ip);
    }

    // Method to retrieve the `sockaddr_in` object
    const sockaddr_in &get_sockaddr() const
    {
        return addr;
    }
};

class MessageHeader
{
private:
public:
    SockAddr sock_addr;
    IcmpHeader icmp_header;

    MessageHeader() {}
    MessageHeader(const SockAddr &t_sock_addr, const IcmpHeader &t_icmp_header)
        : sock_addr(t_sock_addr), icmp_header(t_icmp_header) {}

    msghdr to_native()
    {
        msghdr inner{};
        inner.msg_name = (void *)&sock_addr.get_sockaddr();
        inner.msg_namelen = sizeof(sockaddr_in);

        iovec iov;
        iov.iov_base = const_cast<void *>(static_cast<const void *>(icmp_header.data()));
        iov.iov_len = icmp_header.size();
        inner.msg_iov = &iov;
        inner.msg_iovlen = 1;

        return inner;
    }

    static MessageHeader from_native(const msghdr &hdr)
    {
        if (!hdr.msg_name || hdr.msg_namelen != sizeof(sockaddr_in))
        {
            throw std::invalid_argument("Invalid or missing address in msghdr");
        }

        const sockaddr_in *addr = static_cast<const sockaddr_in *>(hdr.msg_name);
        SockAddr sock_addr(ntohl(addr->sin_addr.s_addr), ntohs(addr->sin_port));

        if (!hdr.msg_iov || hdr.msg_iovlen != 1 || !hdr.msg_iov[0].iov_base)
        {
            throw std::invalid_argument("Invalid or missing iovec in msghdr");
        }

        const uint8_t *icmp_data = static_cast<const uint8_t *>(hdr.msg_iov[0].iov_base + 20);
        size_t icmp_size = hdr.msg_iov[0].iov_len - 20;
        IcmpHeader icmp_header(icmp_data, icmp_size);

        MessageHeader message(sock_addr, icmp_header);
        return message;
    }
};

int main()
{
    std::cout << "Starting program..." << std::endl;

    int socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (socket_fd == -1)
    {
        perror("socket");
        return 1;
    }

    const auto start = std::chrono::steady_clock::now();

    SockAddr dest{"8.8.8.8", 0};
    IcmpHeader icmp_request_data{0x1234, 1};
    MessageHeader request_message_header{dest, icmp_request_data};
    msghdr request_msghdr = request_message_header.to_native();
    ssize_t sent_bytes = sendmsg(socket_fd, &request_msghdr, 0);
    if (sent_bytes < 0)
    {
        perror("sendmsg");
    }

    // std::cout << sent_bytes << std::endl;

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
    if (received_bytes < 0)
    {
        perror("recvfrom");
    }

    // std::cout << received_bytes << std::endl;

    // MessageHeader response_message_header{MessageHeader::from_native(response_msghdr)};

    // std::cout << std::hex << response_message_header.icmp_header.get_sequence_number() << std::endl;

    const auto stop = std::chrono::steady_clock::now();
    std::chrono::duration<double> elapsed_seconds{stop - start};
    // std::cout << elapsed_seconds << std::endl;

    // // Close the socket
    // close(socket_fd);

    std::cout << "Finished" << std::endl;
    return 0;
}
