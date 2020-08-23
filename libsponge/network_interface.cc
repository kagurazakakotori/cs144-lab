#include "network_interface.hh"

#include "arp_message.hh"
#include "ethernet_frame.hh"

// Implementation of a network interface
// Translates from {IP datagram, next hop address} to link-layer frame, and from link-layer frame to IP datagram

using namespace std;

//! \param[in] ethernet_address Ethernet (what ARP calls "hardware") address of the interface
//! \param[in] ip_address IP (what ARP calls "protocol") address of the interface
NetworkInterface::NetworkInterface(const EthernetAddress &ethernet_address, const Address &ip_address)
    : _ethernet_address(ethernet_address), _ip_address(ip_address) {}

//! \param[in] dgram the IPv4 datagram to be sent
//! \param[in] next_hop the IP address of the interface to send it to (typically a router or default gateway, but may also be another host if directly connected to the same network as the destination)
//! (Note: the Address type can be converted to a uint32_t (raw 32-bit IP address) with the Address::ipv4_numeric() method.)
void NetworkInterface::send_datagram(const InternetDatagram &dgram, const Address &next_hop) {
    // convert IP address of next hop to raw 32-bit representation (used in ARP header)
    const uint32_t next_hop_ip = next_hop.ipv4_numeric();

    if (!_arp_table.count(next_hop_ip)) {
        _datagrams_out[next_hop_ip].push(dgram);
        _send_arp_message(ARPMessage::OPCODE_REQUEST, next_hop_ip);
        _arp_table[next_hop_ip] = {ETHERNET_ZERO, false, _current_time + ARP_WAIT_TIME};
        return;
    }

    if (!_arp_table[next_hop_ip].reachable) {
        _datagrams_out[next_hop_ip].push(dgram);

        if (_current_time < _arp_table[next_hop_ip].expire_time) {
            return;
        }

        _send_arp_message(ARPMessage::OPCODE_REQUEST, next_hop_ip);
        _arp_table[next_hop_ip].expire_time = _current_time + ARP_WAIT_TIME;
        return;
    }

    _send_ipv4_datagram(dgram, next_hop_ip);
}

//! \param[in] frame the incoming Ethernet frame
optional<InternetDatagram> NetworkInterface::recv_frame(const EthernetFrame &frame) {
    if (frame.header().dst != _ethernet_address && frame.header().dst != ETHERNET_BROADCAST) {
        return nullopt;
    }

    if (frame.header().type == EthernetHeader::TYPE_IPv4) {
        InternetDatagram dgram;
        if (dgram.parse(frame.payload().concatenate()) == ParseResult::NoError) {
            return dgram;
        }
    } else if (frame.header().type == EthernetHeader::TYPE_ARP) {
        ARPMessage arpmsg;
        if (arpmsg.parse(frame.payload().concatenate()) == ParseResult::NoError) {
            // read arp message if (1) the IP is already in arp table or (2) the target IP is this host
            if (arpmsg.target_ip_address == _ip_address.ipv4_numeric() || _arp_table.count(arpmsg.sender_ip_address)) {
                _arp_table[arpmsg.sender_ip_address] = {
                    arpmsg.sender_ethernet_address, true, _current_time + ARP_STALE_TIME};

                if (arpmsg.opcode == ARPMessage::OPCODE_REQUEST) {
                    _send_arp_message(
                        ARPMessage::OPCODE_REPLY, arpmsg.sender_ip_address, arpmsg.sender_ethernet_address);
                }

                // send queued IP datagrams
                while (!_datagrams_out[arpmsg.sender_ip_address].empty()) {
                    _send_ipv4_datagram(_datagrams_out[arpmsg.sender_ip_address].front(), arpmsg.sender_ip_address);
                    _datagrams_out[arpmsg.sender_ip_address].pop();
                }
            }
        }
    }

    return nullopt;
}

//! \param[in] ms_since_last_tick the number of milliseconds since the last call to this method
void NetworkInterface::tick(const size_t ms_since_last_tick) {
    _current_time += ms_since_last_tick;

    // remove expired arp entries
    for (auto iter = _arp_table.begin(); iter != _arp_table.end(); /* NOTHING */) {
        if (_current_time >= iter->second.expire_time) {
            iter = _arp_table.erase(iter);
        } else {
            iter++;
        }
    }
}

void NetworkInterface::_send_ipv4_datagram(const InternetDatagram &dgram, const uint32_t ipaddr) {
    EthernetFrame frame;

    frame.header().type = EthernetHeader::TYPE_IPv4;
    frame.header().src = _ethernet_address;
    frame.header().dst = _arp_table[ipaddr].ethernet_address;
    frame.payload() = dgram.serialize();

    _frames_out.push(frame);
}

void NetworkInterface::_send_arp_message(const uint16_t opcode,
                                         const uint32_t target_ipaddr,
                                         const EthernetAddress target_ethaddr) {
    ARPMessage arpmsg;
    EthernetFrame frame;

    arpmsg.opcode = opcode;
    arpmsg.sender_ethernet_address = _ethernet_address;
    arpmsg.sender_ip_address = _ip_address.ipv4_numeric();
    arpmsg.target_ethernet_address = (opcode == ARPMessage::OPCODE_REQUEST) ? ETHERNET_ZERO : target_ethaddr;
    arpmsg.target_ip_address = target_ipaddr;

    frame.header().type = EthernetHeader::TYPE_ARP;
    frame.header().src = _ethernet_address;
    frame.header().dst = (opcode == ARPMessage::OPCODE_REQUEST) ? ETHERNET_BROADCAST : target_ethaddr;
    frame.payload() = arpmsg.serialize();

    _frames_out.push(frame);
}
