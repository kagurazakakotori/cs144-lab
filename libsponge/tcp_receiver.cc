#include "tcp_receiver.hh"

// Implementation of a TCP receiver

using namespace std;

bool TCPReceiver::segment_received(const TCPSegment &seg) {
    // ignore duplicate SYN or FIN
    if ((_syn_received && seg.header().syn) || (_fin_received && seg.header().fin)) {
        return false;
    }

    if (!_syn_received) {
        if (!seg.header().syn) {  // drop all segments before received an SYN
            return false;
        }
        // start recive segments when first SYN received
        _syn_received = true;
        _isn = seg.header().seqno;
        _ack_offset += 1;
    }

    uint64_t payload_index = unwrap(seg.header().seqno - _ack_offset, _isn, window_index());
    uint64_t payload_size = seg.payload().size();

    if (payload_size == 0) {
        // If segment’s size is 0 (with no payload and no SYN or FIN flag), then treat it as one byte
        if (!seg.header().syn && !seg.header().fin) {
            _ack_offset += 1;
        }
        if (seg.header().fin) {
            stream_out().end_input();
            _fin_received = true;
            _ack_offset += 1;
        }
        return true;
    }

    if (payload_index >= window_index() + window_size() || payload_index + payload_size <= window_index()) {
        return false;
    }

    _reassembler.push_substring(seg.payload().copy(), payload_index, seg.header().fin);
    if (seg.header().fin) {
        _fin_received = true;
        _ack_offset += 1;
    }

    return true;
}

optional<WrappingInt32> TCPReceiver::ackno() const {
    if (_syn_received) {
        return wrap(window_index(), _isn) + _ack_offset;
    }
    return nullopt;
}

size_t TCPReceiver::window_index() const { return _reassembler.first_unassembled(); }

size_t TCPReceiver::window_size() const { return stream_out().remaining_capacity(); }
