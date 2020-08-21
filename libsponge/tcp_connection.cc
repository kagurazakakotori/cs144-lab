#include "tcp_connection.hh"

#include <iostream>

// Dummy implementation of a TCP connection

// For Lab 4, please replace with a real implementation that passes the
// automated checks run by `make check`.

using namespace std;

size_t TCPConnection::remaining_outbound_capacity() const { return _sender.stream_in().remaining_capacity(); }

size_t TCPConnection::bytes_in_flight() const { return _sender.bytes_in_flight(); }

size_t TCPConnection::unassembled_bytes() const { return _receiver.unassembled_bytes(); }

size_t TCPConnection::time_since_last_segment_received() const { return _time_since_last_received; }

void TCPConnection::segment_received(const TCPSegment &seg) {
    _time_since_last_received = 0;

    // close connection if RST received
    if (seg.header().rst) {
        _receiver.stream_out().set_error();
        _sender.stream_in().set_error();

        _rst_sent = true;
        return;
    }

    // do nothing if SYN has not been received
    _syn_received |= seg.header().syn;
    if (!_syn_received) {
        return;
    }

    // ackno is meaningful only if SYN has been received
    if (seg.header().ack) {
        bool ackno_valid = _sender.ack_received(seg.header().ackno, seg.header().win);

        if (!ackno_valid) {  // (3) TCPSender thinks the ackno is invalid
            _sender.send_empty_segment();
        } else {
            _sender.fill_window();
        }
    }

    bool segment_acceptable = _receiver.segment_received(seg);  // this also updates ackno

    // step 2 of 3-way handshaking, send SYN-ACK if SYN is received
    if (!_syn_sent) {
        connect();
        return;
    }

    // spit out an empty segment if
    // (1) incoming segment occupies any sequence numbers
    if (segment_acceptable && seg.length_in_sequence_space() > 0) {
        _sender.send_empty_segment();
    }

    // (2) TCPReceiver thinks the segment is unacceptable
    if (!segment_acceptable) {
        _sender.send_empty_segment();
    }

    _send_segments();
}

bool TCPConnection::active() const {
    bool unclean_shutdown = _rst_received || _rst_sent;
    bool clean_shutdown = (unassembled_bytes() == 0) && _receiver.stream_out().eof() && _sender.stream_in().eof() &&
                          (bytes_in_flight() == 0) &&
                          (!_linger_after_streams_finish || _time_since_last_received >= 10 * _cfg.rt_timeout);

    return !(unclean_shutdown || clean_shutdown);
}

size_t TCPConnection::write(const string &data) {
    size_t bytes_written = _sender.stream_in().write(data);

    _sender.fill_window();
    _send_segments();

    return bytes_written;
}

//! \param[in] ms_since_last_tick number of milliseconds since the last call to this method
void TCPConnection::tick(const size_t ms_since_last_tick) {
    _time_since_last_received += ms_since_last_tick;

    _sender.tick(ms_since_last_tick);
    _send_segments();
}

void TCPConnection::end_input_stream() {
    _sender.stream_in().end_input();
    _sender.fill_window();
    _send_segments();
}

void TCPConnection::connect() {
    _sender.fill_window();
    _send_segments();

    _syn_sent = true;
}

TCPConnection::~TCPConnection() {
    try {
        if (active()) {
            cerr << "Warning: Unclean shutdown of TCPConnection\n";

            // send a RST segment to the peer
            _send_rst();
        }
    } catch (const exception &e) {
        std::cerr << "Exception destructing TCP FSM: " << e.what() << std::endl;
    }
}

void TCPConnection::_send_segments() {
    // abort connection if the sender has sent too many consecutive retransmissions without success
    if (_sender.consecutive_retransmissions() > TCPConfig::MAX_RETX_ATTEMPTS) {
        _send_rst();
        return;
    }

    while (!_sender.segments_out().empty()) {
        TCPSegment &seg = _sender.segments_out().front();

        if (_receiver.ackno().has_value()) {
            seg.header().ack = true;
            seg.header().ackno = _receiver.ackno().value();
        }
        seg.header().win = _receiver.window_size();

        _segments_out.push(seg);
        _sender.segments_out().pop();
    }

    // update linger option
    if (_receiver.stream_out().input_ended() && !_sender.stream_in().eof()) {
        _linger_after_streams_finish = false;
    }
}

void TCPConnection::_send_rst() {
    _receiver.stream_out().set_error();
    _sender.stream_in().set_error();
    _sender.send_empty_segment();  // generate an empty segment in sender's queue to ensure it it not empty

    TCPSegment &seg = _sender.segments_out().front();
    seg.header().rst = true;
    if (_receiver.ackno().has_value()) {
        seg.header().ack = true;
        seg.header().ackno = _receiver.ackno().value();
    }

    _segments_out.push(seg);
    _sender.segments_out().pop();

    _rst_sent = true;
}
