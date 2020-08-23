#ifndef SPONGE_LIBSPONGE_NETWORK_INTERFACE_HH
#define SPONGE_LIBSPONGE_NETWORK_INTERFACE_HH

#include "ethernet_frame.hh"
#include "tcp_over_ip.hh"
#include "tun.hh"

#include <optional>
#include <queue>
#include <unordered_map>

//! Zero Ethernet address (00:00:00:00:00:00)
// RFC 5227, 2.1.1, for ARP requests, the 'target hardware address' field is ignored and SHOULD be set to all zeroes.
constexpr EthernetAddress ETHERNET_ZERO = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

constexpr uint64_t ARP_WAIT_TIME = 5000;
constexpr uint64_t ARP_STALE_TIME = 30000;

struct ARPTableEntry {
    EthernetAddress ethernet_address;
    bool reachable;
    uint64_t expire_time;
};

//! \brief A "network interface" that connects IP (the internet layer, or network layer)
//! with Ethernet (the network access layer, or link layer).

//! This module is the lowest layer of a TCP/IP stack
//! (connecting IP with the lower-layer network protocol,
//! e.g. Ethernet). But the same module is also used repeatedly
//! as part of a router: a router generally has many network
//! interfaces, and the router's job is to route Internet datagrams
//! between the different interfaces.

//! The network interface translates datagrams (coming from the
//! "customer," e.g. a TCP/IP stack or router) into Ethernet
//! frames. To fill in the Ethernet destination address, it looks up
//! the Ethernet address of the next IP hop of each datagram, making
//! requests with the [Address Resolution Protocol](\ref rfc::rfc826).
//! In the opposite direction, the network interface accepts Ethernet
//! frames, checks if they are intended for it, and if so, processes
//! the the payload depending on its type. If it's an IPv4 datagram,
//! the network interface passes it up the stack. If it's an ARP
//! request or reply, the network interface processes the frame
//! and learns or replies as necessary.
class NetworkInterface {
  private:
    //! Ethernet (known as hardware, network-access-layer, or link-layer) address of the interface
    EthernetAddress _ethernet_address;

    //! IP (known as internet-layer or network-layer) address of the interface
    Address _ip_address;

    //! time since NetworkInterface constructed in milliseconds
    //! use uint64_t to store time, not considering overflow since it can hold 584 billion years from now
    //! trust me, this code wont work such a long time
    uint64_t _current_time = 0;

    //! outbound queue of Ethernet frames that the NetworkInterface wants sent
    std::queue<EthernetFrame> _frames_out{};

    std::unordered_map<uint32_t, std::queue<InternetDatagram>> _datagrams_out{};

    std::unordered_map<uint32_t, ARPTableEntry> _arp_table{};

    //! \brief Sends an IPv4 datagram, encapsulated in an Ethernet frame, for a reachable IP address
    void _send_ipv4_datagram(const InternetDatagram &dgram, const uint32_t ipaddr);

    //! \brief Sends an ARP message, encapsulated in an Ethernet frame
    //! \note When opcode is request (1), target_ethaddr will be ignored
    void _send_arp_message(const uint16_t opcode,
                           const uint32_t target_ipaddr,
                           const EthernetAddress target_ethaddr = ETHERNET_ZERO);

  public:
    //! \brief Construct a network interface with given Ethernet (network-access-layer) and IP (internet-layer) addresses
    NetworkInterface(const EthernetAddress &ethernet_address, const Address &ip_address);

    //! \brief Access queue of Ethernet frames awaiting transmission
    std::queue<EthernetFrame> &frames_out() { return _frames_out; }

    //! \brief Sends an IPv4 datagram, encapsulated in an Ethernet frame (if it knows the Ethernet destination address).

    //! Will need to use [ARP](\ref rfc::rfc826) to look up the Ethernet destination address for the next hop
    //! ("Sending" is accomplished by pushing the frame onto the frames_out queue.)
    void send_datagram(const InternetDatagram &dgram, const Address &next_hop);

    //! \brief Receives an Ethernet frame and responds appropriately.

    //! If type is IPv4, returns the datagram.
    //! If type is ARP request, learn a mapping from the "sender" fields, and send an ARP reply.
    //! If type is ARP reply, learn a mapping from the "target" fields.
    std::optional<InternetDatagram> recv_frame(const EthernetFrame &frame);

    //! \brief Called periodically when time elapses
    void tick(const size_t ms_since_last_tick);
};

#endif  // SPONGE_LIBSPONGE_NETWORK_INTERFACE_HH
