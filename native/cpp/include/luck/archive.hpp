#ifndef LUCK_CPP_ARCHIVE_HPP
#define LUCK_CPP_ARCHIVE_HPP

#include <cstddef>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>
#include "luck/model.hpp"

namespace luck {

struct ArchiveLimits {
    std::size_t maximum_bytes{16U*1024U*1024U};
    std::size_t maximum_cookies{100000U};
    std::size_t maximum_string_bytes{2U*1024U*1024U};
};

struct ArchiveHeader {
    std::uint16_t version{0U};
    std::uint32_t cookie_count{0U};
    std::uint64_t payload_bytes{0U};
    std::uint64_t checksum{0U};
};

struct ArchiveDecodeResult {
    ArchiveHeader header;
    std::vector<Cookie> cookies;
    std::size_t trailing_bytes{0U};
};

class ArchiveError final:public std::runtime_error {
public:
    explicit ArchiveError(const std::string& message):std::runtime_error(message){}
};

[[nodiscard]] std::vector<std::byte> encode_archive(const std::vector<Cookie>& cookies);
[[nodiscard]] ArchiveDecodeResult decode_archive(std::span<const std::byte> input,const ArchiveLimits& limits={});
[[nodiscard]] std::uint64_t archive_checksum(std::span<const std::byte> input) noexcept;

}
#endif
