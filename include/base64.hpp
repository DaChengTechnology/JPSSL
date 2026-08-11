#pragma once
/**
 * base64.hpp -- RFC 4648 base64 (used by CT HTTP API: add-chain, get-entries, ...)
 */
#include <cstddef>
#include <cstdint>
#include "jpssl_optional.hpp"
#include <string>
#include <vector>

namespace jpssl {

/// Encode bytes as standard base64 (RFC 4648 section 4) with '=' padding.
std::string base64_encode(const uint8_t* data, size_t len);
std::string base64_encode(const std::vector<uint8_t>& data);

/// Decode standard base64. Missing padding is accepted; invalid characters
/// or a non-canonical trailing group fail and return nullopt.
jpssl::optional<std::vector<uint8_t>> base64_decode(const std::string& text);

} // namespace jpssl
