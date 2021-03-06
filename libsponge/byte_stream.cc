#include "byte_stream.hh"

#include <algorithm>
#include <iterator>
#include <stdexcept>

// Implementation of a flow-controlled in-memory byte stream.

using namespace std;

ByteStream::ByteStream(const size_t capacity) : _capacity(capacity) {}

size_t ByteStream::write(const string &data) {
    size_t bytes_to_write = min(data.size(), remaining_capacity());
    _buffer.insert(_buffer.end(), data.begin(), data.begin() + bytes_to_write);
    _bytes_written += bytes_to_write;
    return bytes_to_write;
}

//! \param[in] len bytes will be copied from the output side of the buffer
string ByteStream::peek_output(const size_t len) const {
    return string(_buffer.begin(), _buffer.begin() + min(len, buffer_size()));
}

//! \param[in] len bytes will be removed from the output side of the buffer
void ByteStream::pop_output(const size_t len) {
    size_t bytes_to_pop = min(len, buffer_size());
    _buffer.erase(_buffer.begin(), _buffer.begin() + bytes_to_pop);
    _bytes_read += bytes_to_pop;
}

void ByteStream::end_input() { _input_ended = true; }

bool ByteStream::input_ended() const { return _input_ended; }

size_t ByteStream::buffer_size() const { return _buffer.size(); }

bool ByteStream::buffer_empty() const { return _buffer.empty(); }

bool ByteStream::eof() const { return input_ended() && buffer_empty(); }

size_t ByteStream::bytes_written() const { return _bytes_written; }

size_t ByteStream::bytes_read() const { return _bytes_read; }

size_t ByteStream::remaining_capacity() const { return _capacity - buffer_size(); }
