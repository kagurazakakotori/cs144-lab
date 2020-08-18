#include "wrapping_integers.hh"

// Implementation of a 32-bit wrapping integer

using namespace std;

//! Transform an "absolute" 64-bit sequence number (zero-indexed) into a WrappingInt32
//! \param n The input absolute 64-bit sequence number
//! \param isn The initial sequence number
WrappingInt32 wrap(uint64_t n, WrappingInt32 isn) {
    uint32_t input = n & 0xffffffff;
    return isn + input;
}

//! Transform a WrappingInt32 into an "absolute" 64-bit sequence number (zero-indexed)
//! \param n The relative sequence number
//! \param isn The initial sequence number
//! \param checkpoint A recent absolute 64-bit sequence number
//! \returns the 64-bit sequence number that wraps to `n` and is closest to `checkpoint`
//!
//! \note Each of the two streams of the TCP connection has its own ISN. One stream
//! runs from the local TCPSender to the remote TCPReceiver and has one ISN,
//! and the other stream runs from the remote TCPSender to the local TCPReceiver and
//! has a different ISN.
uint64_t unwrap(WrappingInt32 n, WrappingInt32 isn, uint64_t checkpoint) {
    uint32_t offset = n - isn;
    uint64_t abs_seq = ((checkpoint >> 32) << 32) | offset;

    // avoid overflow when comparing diff later
    if (abs_seq < checkpoint) {
        abs_seq += (1ul << 32);
    }

    if (abs_seq >= (1ul << 32)) {
        if (abs_seq - checkpoint > checkpoint - (abs_seq - (1ul << 32))) {
            abs_seq -= (1ul << 32);
        }
    }

    return abs_seq;
}
