#include "tcp_receiver.hh"

// Implementation of a TCP receiver

using namespace std;

bool TCPReceiver::segment_received(const TCPSegment &seg) {
    // reject duplicate SYN or FIN
    if ((_syn_received && seg.header().syn) || (_fin_received && seg.header().fin)) {
        return false;
    }

    if (!_syn_received) {
        // drop all segments before received first SYN
        if (!seg.header().syn) {
            return false;
        }

        // start recive segments when first SYN received
        _syn_received = true;
        _isn = seg.header().seqno;
    }

    if (seg.header().fin) {
        _fin_received = true;
    }

    size_t segment_seqno = unwrap(seg.header().seqno, _isn, _reassembler.first_unassembled());
    size_t segment_size = seg.length_in_sequence_space() - seg.header().syn - seg.header().fin;
    if (segment_size == 0) {  // if segment’s length is 0, treat it as one byte
        segment_size = 1;
    }

    size_t win_seqno = unwrap(_ackno, _isn, _reassembler.first_unassembled());  // ackno() always has value here
    size_t win_size = (window_size() == 0) ? 1 : window_size();  // if window size is 0, treat it as one byte

    // reject segments with none of its sequence numbers falls inside the window, except SYN and FIN segments
    bool outside_window = segment_seqno + segment_size <= win_seqno || segment_seqno >= win_seqno + win_size;
    if (outside_window && !seg.header().syn && !seg.header().fin) {
        return false;
    }

    _reassembler.push_substring(seg.payload().copy(), segment_seqno - 1, seg.header().fin);  // minus 1 for SYN

    // update ackno, FIN should be acknowledged after received all payloads
    bool finished = _fin_received && (_reassembler.unassembled_bytes() == 0);
    _ackno = wrap(_reassembler.first_unassembled() + 1 + finished, _isn);  // add 1 for SYN, 1 for FIN

    return true;
}

optional<WrappingInt32> TCPReceiver::ackno() const {
    if (_syn_received) {
        return _ackno;
    }
    return nullopt;
}

size_t TCPReceiver::window_size() const { return stream_out().remaining_capacity(); }
