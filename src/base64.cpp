#include "base64.hpp"

#include <algorithm>

namespace jpssl {
namespace {

const char B64_ALPHABET[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

inline int b64_value(uint8_t c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

} // namespace

std::string base64_encode(const uint8_t* data, size_t len) {
    std::string out;
    out.reserve(((len + 2) / 3) * 4);

    size_t i = 0;
    while (i + 3 <= len) {
        uint32_t v = (uint32_t)data[i] << 16 | (uint32_t)data[i + 1] << 8 | data[i + 2];
        out.push_back(B64_ALPHABET[(v >> 18) & 0x3F]);
        out.push_back(B64_ALPHABET[(v >> 12) & 0x3F]);
        out.push_back(B64_ALPHABET[(v >> 6) & 0x3F]);
        out.push_back(B64_ALPHABET[v & 0x3F]);
        i += 3;
    }

    size_t rem = len - i;
    if (rem == 1) {
        uint32_t v = (uint32_t)data[i] << 16;
        out.push_back(B64_ALPHABET[(v >> 18) & 0x3F]);
        out.push_back(B64_ALPHABET[(v >> 12) & 0x3F]);
        out.push_back('=');
        out.push_back('=');
    } else if (rem == 2) {
        uint32_t v = (uint32_t)data[i] << 16 | (uint32_t)data[i + 1] << 8;
        out.push_back(B64_ALPHABET[(v >> 18) & 0x3F]);
        out.push_back(B64_ALPHABET[(v >> 12) & 0x3F]);
        out.push_back(B64_ALPHABET[(v >> 6) & 0x3F]);
        out.push_back('=');
    }
    return out;
}

std::string base64_encode(const std::vector<uint8_t>& data) {
    return base64_encode(data.data(), data.size());
}

std::optional<std::vector<uint8_t>> base64_decode(const std::string& text) {
    if (text.size() % 4 != 0) return std::nullopt;

    std::vector<uint8_t> out;
    out.reserve((text.size() / 4) * 3);

    size_t i = 0;
    while (i < text.size()) {
        int a = b64_value((uint8_t)text[i]);
        int b = b64_value((uint8_t)text[i + 1]);
        int c = text[i + 2] == '=' ? -2 : b64_value((uint8_t)text[i + 2]);
        int d = text[i + 3] == '=' ? -2 : b64_value((uint8_t)text[i + 3]);
        if (a < 0 || b < 0 || c == -1 || d == -1) return std::nullopt;

        uint32_t v = (uint32_t)a << 18 | (uint32_t)b << 12;
        if (c >= 0) v |= (uint32_t)c << 6;
        if (d >= 0) v |= (uint32_t)d;

        out.push_back((uint8_t)(v >> 16));
        if (c >= 0) out.push_back((uint8_t)(v >> 8));
        if (d >= 0) out.push_back((uint8_t)v);

        // Padding, if present, must only occur in the final group.
        bool padded = text[i + 2] == '=' || text[i + 3] == '=';
        if (padded && i + 4 != text.size()) return std::nullopt;
        i += 4;
    }
    return out;
}

} // namespace jpssl
