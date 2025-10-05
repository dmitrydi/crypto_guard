#pragma once

#include <istream>
#include <iterator>
#include <stdexcept>
#include <vector>

namespace GryptoGuard::Utility {

inline std::pair<std::istream_iterator<unsigned char>, size_t>
read_block(std::istream_iterator<unsigned char> iter, std::vector<unsigned char> &out_buff, size_t block_size) {
    out_buff.clear();
    out_buff.reserve(block_size);
    size_t cntr{};
    for (size_t i = 0; i < block_size; ++i) {
        // Check if we've reached the end of stream
        if (iter == std::istream_iterator<unsigned char>()) {
            break;
        }

        // Copy the current character and advance iterator
        out_buff.push_back(*iter);
        ++iter;
        ++cntr;
    }

    return {iter, cntr};
}

}  // namespace GryptoGuard::Utility