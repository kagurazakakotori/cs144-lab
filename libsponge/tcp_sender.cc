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
    // calculate current sliding window capacity
    // when window size is 0, act like window size is 1, "zero window probing"
    size_t window_capacity = ((_window_size == 0) ? 1 : _window_size) - _outstanding_size;

    // never send any segments after FIN is sent
    while (!_fin_sent && window_capacity > 0) {
        TCPSegment seg;

        if (_next_seqno == 0) {  // send initial SYN
            seg.header().syn = true;
        } else if (_stream.eof()) {  // send FIN when there is no mo bytes in ByteStream
            seg.header().fin = true;
            _fin_sent = true;
        } else if (!_stream.buffer_empty()) {
            seg.payload() = Buffer(move(_stream.read(min(window_capacity, TCPConfig::MAX_PAYLOAD_SIZE))));

            // handle piggyback FIN, MUST ensure the sliding window can hold it
            if (_stream.eof() && window_capacity - seg.length_in_sequence_space() > 0) {
                seg.header().fin = true;
                _fin_sent = true;
            }
        } else {
            return;
        }
        seg.header().seqno = wrap(_next_seqno, _isn);

        _next_seqno += seg.length_in_sequence_space();
        _outstanding_size += seg.length_in_sequence_space();
        window_capacity -= seg.length_in_sequence_space();
        _segments_outstanding.push(seg);
        _segments_out.push(seg);
    }
}

//! \param ackno The remote receiver's ackno (acknowledgment number)
//! \param window_size The remote receiver's advertised window size
//! \returns `false` if the ackno appears invalid (acknowledges something the TCPSender hasn't sent yet)
bool TCPSender::ack_received(const WrappingInt32 ackno, const uint16_t window_size) {
    uint64_t abs_ackno = unwrap(ackno, _isn, _last_ackno);
    if (abs_ackno > next_seqno_absolute()) {
        return false;
    }

    _window_size = window_size;

    // if received ack of an acknowledged packet, do nothing
    if (abs_ackno <= _last_ackno) {
        return true;
    }
    _last_ackno = abs_ackno;

    while (!_segments_outstanding.empty()) {
        TCPSegment &seg = _segments_outstanding.front();
        uint64_t abs_seqno = unwrap(seg.header().seqno, _isn, _last_ackno);

        if (abs_ackno >= abs_seqno + seg.length_in_sequence_space()) {
            _outstanding_size -= seg.length_in_sequence_space();
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
        if (!_segments_outstanding.empty()) {
            _segments_out.push(_segments_outstanding.front());

            if (_window_size != 0) {
                // increment the number of consecutive retransmissions
                _consecutive_retransmissions += 1;
                // double the value of RTO
                _retransmission_timeout *= 2;
            }
        }

        // always reset the retransmission timer
        _retransmission_timer = 0;
    }
}

unsigned int TCPSender::consecutive_retransmissions() const { return _consecutive_retransmissions; }

void TCPSender::send_empty_segment() {
    TCPSegment seg;
    seg.header().seqno = wrap(_next_seqno, _isn);
    _segments_out.push(seg);
}
