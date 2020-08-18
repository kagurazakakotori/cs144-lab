#include "tcp_sender.hh"

#include "tcp_config.hh"

#include <random>

// Implementation of a TCP sender

using namespace std;

//! \param[in] capacity the capacity of the outgoing byte stream
//! \param[in] retx_timeout the initial amount of time to wait before retransmitting the oldest outstanding segment
//! \param[in] fixed_isn the Initial Sequence Number to use, if set (otherwise uses a random ISN)
TCPSender::TCPSender(const size_t capacity, const uint16_t retx_timeout, const std::optional<WrappingInt32> fixed_isn)
    : _isn(fixed_isn.value_or(WrappingInt32{random_device()()}))
    , _initial_retransmission_timeout{retx_timeout}
    , _retransmission_timeout{retx_timeout}
    , _stream(capacity) {}

uint64_t TCPSender::bytes_in_flight() const { return _outstanding_size; }

void TCPSender::fill_window() {
    // never send any segments after FIN is sent
    while (!_fin_sent && _window_capacity > 0) {
        TCPSegment seg;

        if (_next_seqno == 0) {  // send initial SYN
            seg.header().syn = true;
        } else if (_stream.eof()) {  // send FIN when there is no mo bytes in ByteStream
            seg.header().fin = true;
            _fin_sent = true;
        } else if (!_stream.buffer_empty()) {
            size_t payload_size = min(_window_capacity, TCPConfig::MAX_PAYLOAD_SIZE);
            seg.payload() = Buffer(move(_stream.read(payload_size)));
            if (_stream.eof()) {  // piggyback FIN
                seg.header().fin = true;
                _fin_sent = true;
            }
        } else {
            return;
        }
        seg.header().seqno = wrap(_next_seqno, _isn);

        _next_seqno += seg.length_in_sequence_space();
        _outstanding_size += seg.length_in_sequence_space();
        _window_capacity -= seg.length_in_sequence_space();
        _segments_outstanding.push(seg);
        _segments_out.push(seg);
    }
}

//! \param ackno The remote receiver's ackno (acknowledgment number)
//! \param window_size The remote receiver's advertised window size
//! \returns `false` if the ackno appears invalid (acknowledges something the TCPSender hasn't sent yet)
bool TCPSender::ack_received(const WrappingInt32 ackno, const uint16_t window_size) {
    if (ackno - next_seqno() > 0) {
        return false;
    }

    _window_size = window_size;
    _window_capacity = window_size;

    // remove all fully-acknowledged segments
    while (!_segments_outstanding.empty()) {
        auto &segment = _segments_outstanding.front();
        if (ackno - segment.header().seqno >= static_cast<int32_t>(segment.length_in_sequence_space())) {
            _outstanding_size -= segment.length_in_sequence_space();
            _segments_outstanding.pop();
        } else {
            break;
        }
    }

    // Set RTO back to its "initial value."
    _retransmission_timeout = _initial_retransmission_timeout;

    // If the sender has any outstanding data, restart the retransmission timer
    if (!_segments_outstanding.empty()) {
        _retransmission_timer = 0;
    }

    // Reset the count of "consecutive retransmissions" back to zero
    _consecutive_retransmissions = 0;

    return true;
}

//! \param[in] ms_since_last_tick the number of milliseconds since the last call to this method
void TCPSender::tick(const size_t ms_since_last_tick) {
    _retransmission_timer += ms_since_last_tick;

    if (_retransmission_timer >= _retransmission_timeout) {
        // retransmit the earliest segment
        _segments_out.push(_segments_outstanding.front());

        if (_window_size != 0) {
            // increment the number of consecutive retransmissions
            _consecutive_retransmissions += 1;
            // double the value of RTO
            _retransmission_timeout *= 2;
        }

        // Start the retransmission timer
        _retransmission_timer = 0;
    }
}

unsigned int TCPSender::consecutive_retransmissions() const { return _consecutive_retransmissions; }

void TCPSender::send_empty_segment() {
    TCPSegment seg;
    seg.header().seqno = wrap(_next_seqno, _isn);
    _segments_out.push(seg);
}
