#include "stream_reassembler.hh"

// Implementation of a stream reassembler.

using namespace std;

StreamReassembler::StreamReassembler(const size_t capacity) : _output(capacity), _capacity(capacity) {}

//! \details This function accepts a substring (aka a segment) of bytes,
//! possibly out-of-order, from the logical stream, and assembles any newly
//! contiguous substrings and writes them into the output stream in order.
void StreamReassembler::push_substring(const string &data, const size_t index, const bool eof) {
    _has_eof |= eof;
    
    size_t unacceptable_index = _next_index + (_capacity - _output.buffer_size());

    // ignore empty or outputed segments
    if (data.empty() || index + data.size() <= _next_index || index >= unacceptable_index) {
        if (empty() && _has_eof) {
            _output.end_input();
        }
        return;
    }

    // trim input to ensure index >= _next_index and it fits in the buffer
    size_t trimmed_index = max(index, _next_index);
    size_t trimmed_end = min(index + data.size(), unacceptable_index);
    size_t trimmed_size = trimmed_end - trimmed_index;

    // ensure no overlapping segments
    for (auto iter = _unassembled_segments.begin(); iter != _unassembled_segments.end(); /* NOTHING */) {
        auto segment_index = iter->first;
        auto segment_end = segment_index + iter->second.size();

        if (trimmed_index >= segment_index && trimmed_end <= segment_end) {  // ignore when data is subset of a segment
            return;
        } else if (trimmed_index <= segment_index && trimmed_end >= segment_end) {  // segment is subset of data, remove
            _unassembled_bytes -= iter->second.size();
            iter = _unassembled_segments.erase(iter);
            continue;
        } else if (trimmed_index < segment_index && trimmed_end > segment_index) {
            trimmed_size = segment_index - trimmed_index;
        } else if (trimmed_index < segment_end && trimmed_end > segment_end) {
            trimmed_index = segment_end;
            trimmed_size = trimmed_end - segment_end;
        }
        iter++;
    }

    // insert the segment
    _unassembled_bytes += trimmed_size;
    _unassembled_segments[trimmed_index] = data.substr(trimmed_index - index, trimmed_size);

    // try to output as much as it can
    for (auto iter = _unassembled_segments.begin(); iter != _unassembled_segments.end(); /* NOTHING */) {
        if (iter->first != _next_index) {
            break;
        }

        size_t bytes_written = _output.write(iter->second);
        _unassembled_bytes -= bytes_written;
        _next_index += bytes_written;

        iter = _unassembled_segments.erase(iter);
    }

    if (empty() && _has_eof) {
        _output.end_input();
    }
}

size_t StreamReassembler::first_unassembled() const { return _next_index; }

size_t StreamReassembler::unassembled_bytes() const { return _unassembled_bytes; }

bool StreamReassembler::empty() const { return _unassembled_segments.empty(); }
