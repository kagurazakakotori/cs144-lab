#include "router.hh"

using namespace std;

// Implementation of an IP router

//! \param[in] route_prefix The "up-to-32-bit" IPv4 address prefix to match the datagram's destination address against
//! \param[in] prefix_length For this route to be applicable, how many high-order (most-significant) bits of the route_prefix will need to match the corresponding bits of the datagram's destination address?
//! \param[in] next_hop The IP address of the next hop. Will be empty if the network is directly attached to the router (in which case, the next hop address should be the datagram's final destination).
//! \param[in] interface_num The index of the interface to send the datagram out on.
void Router::add_route(const uint32_t route_prefix,
                       const uint8_t prefix_length,
                       const optional<Address> next_hop,
                       const size_t interface_num) {
    _routing_table[prefix_length][route_prefix] = {next_hop, interface_num};
}

//! \param[in] dgram The datagram to be routed
void Router::route_one_datagram(InternetDatagram &dgram) {
    for (int i = 32; i >= 0; i--) {
        const uint32_t prefix_to_match = dgram.header().dst & SUBNET_MASK[i];

        if (_routing_table[i].count(prefix_to_match)) {
            // if ttl is already reached zero or is going to reach zero, drop the datagram
            // router only decrements the TTL if it is forwarding the datagram
            if (dgram.header().ttl <= 1) {
                return;
            }

            dgram.header().ttl -= 1;

            Address next_hop =
                _routing_table[i][prefix_to_match].next_hop.value_or(Address::from_ipv4_numeric(dgram.header().dst));
            interface(_routing_table[i][prefix_to_match].interface_num).send_datagram(dgram, next_hop);
            return;
        }
    }
}

void Router::route() {
    // Go through all the interfaces, and route every incoming datagram to its proper outgoing interface.
    for (auto &interface : _interfaces) {
        auto &queue = interface.datagrams_out();
        while (!queue.empty()) {
            route_one_datagram(queue.front());
            queue.pop();
        }
    }
}
