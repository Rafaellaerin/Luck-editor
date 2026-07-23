#include "luck/archive.hpp"
#include <array>
#include <bit>
#include <cstring>
#include <limits>
#include <type_traits>
#include <utility>

namespace luck {
namespace {
constexpr std::array<std::byte,8U> magic{
    std::byte{'L'},std::byte{'U'},std::byte{'C'},std::byte{'K'},std::byte{'C'},std::byte{'K'},std::byte{'0'},std::byte{'1'}};
constexpr std::uint16_t version=1U;
constexpr std::uint16_t flag_secure=1U<<0U;
constexpr std::uint16_t flag_http_only=1U<<1U;
constexpr std::uint16_t flag_session=1U<<2U;
constexpr std::uint16_t flag_host_only=1U<<3U;
constexpr std::uint16_t flag_partitioned=1U<<4U;

class Writer {
public:
    void append(std::span<const std::byte> bytes){ data_.insert(data_.end(),bytes.begin(),bytes.end()); }
    void u8(std::uint8_t value){ data_.push_back(static_cast<std::byte>(value)); }
    void u16(std::uint16_t value){ integer(value); }
    void u32(std::uint32_t value){ integer(value); }
    void u64(std::uint64_t value){ integer(value); }
    void f64(double value){ u64(std::bit_cast<std::uint64_t>(value)); }
    void string(std::string_view value) {
        if (value.size()>std::numeric_limits<std::uint32_t>::max()) throw ArchiveError("string is too large for archive format");
        u32(static_cast<std::uint32_t>(value.size()));
        append(std::as_bytes(std::span{value.data(),value.size()}));
    }
    [[nodiscard]] const std::vector<std::byte>& data() const noexcept { return data_; }
    [[nodiscard]] std::vector<std::byte> take() && { return std::move(data_); }
private:
    template<class Integer> void integer(Integer value) {
        static_assert(std::is_unsigned_v<Integer>);
        for (std::size_t shift=0U;shift<sizeof(Integer);shift+=1U)
            data_.push_back(static_cast<std::byte>((value>>(shift*8U))&static_cast<Integer>(0xffU)));
    }
    std::vector<std::byte> data_;
};

class Reader {
public:
    explicit Reader(std::span<const std::byte> input):input_(input){}
    [[nodiscard]] std::size_t remaining() const noexcept { return input_.size()-position_; }
    std::span<const std::byte> take(std::size_t count) {
        if (count>remaining()) throw ArchiveError("unexpected end of archive at byte "+std::to_string(position_));
        const auto result=input_.subspan(position_,count); position_+=count; return result;
    }
    std::uint8_t u8(){ return std::to_integer<std::uint8_t>(take(1U).front()); }
    std::uint16_t u16(){ return integer<std::uint16_t>(); }
    std::uint32_t u32(){ return integer<std::uint32_t>(); }
    std::uint64_t u64(){ return integer<std::uint64_t>(); }
    double f64(){ return std::bit_cast<double>(u64()); }
    std::string string(std::size_t maximum) {
        const auto length=static_cast<std::size_t>(u32());
        if (length>maximum) throw ArchiveError("archive string exceeds configured limit");
        const auto bytes=take(length);
        return {reinterpret_cast<const char*>(bytes.data()),bytes.size()};
    }
private:
    template<class Integer> Integer integer() {
        static_assert(std::is_unsigned_v<Integer>);
        const auto bytes=take(sizeof(Integer));
        std::uint64_t value=0U;
        for (std::size_t index=0U;index<sizeof(Integer);index+=1U)
            value|=static_cast<std::uint64_t>(std::to_integer<unsigned int>(bytes[index]))<<(index*8U);
        return static_cast<Integer>(value);
    }
    std::span<const std::byte> input_; std::size_t position_{0U};
};

void encode_cookie(Writer& writer,const Cookie& cookie) {
    writer.string(cookie.name); writer.string(cookie.value); writer.string(cookie.domain); writer.string(cookie.path);
    writer.string(cookie.store_id); writer.string(cookie.partition_site);
    std::uint16_t flags=0U;
    if (cookie.secure) flags|=flag_secure;
    if (cookie.http_only) flags|=flag_http_only;
    if (cookie.session) flags|=flag_session;
    if (cookie.host_only) flags|=flag_host_only;
    if (cookie.partitioned) flags|=flag_partitioned;
    writer.u16(flags);
    switch (cookie.same_site) {
        case SameSite::unspecified:writer.u8(0U);break;
        case SameSite::none:writer.u8(1U);break;
        case SameSite::lax:writer.u8(2U);break;
        case SameSite::strict:writer.u8(3U);break;
    }
    if (cookie.expiration_date.has_value()) { writer.u8(1U); writer.f64(*cookie.expiration_date); }
    else writer.u8(0U);
}

Cookie decode_cookie(Reader& reader,const ArchiveLimits& limits) {
    Cookie cookie;
    cookie.name=reader.string(limits.maximum_string_bytes);
    cookie.value=reader.string(limits.maximum_string_bytes);
    cookie.domain=reader.string(limits.maximum_string_bytes);
    cookie.path=reader.string(limits.maximum_string_bytes);
    cookie.store_id=reader.string(limits.maximum_string_bytes);
    cookie.partition_site=reader.string(limits.maximum_string_bytes);
    const auto flags=reader.u16();
    cookie.secure=(flags&flag_secure)!=0U;
    cookie.http_only=(flags&flag_http_only)!=0U;
    cookie.session=(flags&flag_session)!=0U;
    cookie.host_only=(flags&flag_host_only)!=0U;
    cookie.partitioned=(flags&flag_partitioned)!=0U;
    switch (reader.u8()) {
        case 0U:cookie.same_site=SameSite::unspecified;break;
        case 1U:cookie.same_site=SameSite::none;break;
        case 2U:cookie.same_site=SameSite::lax;break;
        case 3U:cookie.same_site=SameSite::strict;break;
        default:throw ArchiveError("archive contains an invalid SameSite tag");
    }
    switch (reader.u8()) {
        case 0U:cookie.expiration_date.reset();break;
        case 1U:cookie.expiration_date=reader.f64();break;
        default:throw ArchiveError("archive contains an invalid expiration tag");
    }
    return cookie;
}
}

std::vector<std::byte> encode_archive(const std::vector<Cookie>& cookies) {
    if (cookies.size()>std::numeric_limits<std::uint32_t>::max()) throw ArchiveError("too many cookies for archive format");
    Writer payload;
    for (const auto& cookie:cookies) encode_cookie(payload,cookie);
    Writer output;
    output.append(magic); output.u16(version); output.u16(0U); output.u32(static_cast<std::uint32_t>(cookies.size()));
    output.u64(static_cast<std::uint64_t>(payload.data().size())); output.u64(archive_checksum(payload.data())); output.append(payload.data());
    return std::move(output).take();
}

ArchiveDecodeResult decode_archive(std::span<const std::byte> input,const ArchiveLimits& limits) {
    if (input.size()>limits.maximum_bytes) throw ArchiveError("archive exceeds configured byte limit");
    Reader reader(input);
    if (!std::ranges::equal(reader.take(magic.size()),magic)) throw ArchiveError("archive magic is invalid");
    ArchiveDecodeResult result;
    result.header.version=reader.u16();
    if (result.header.version!=version) throw ArchiveError("unsupported archive version");
    if (reader.u16()!=0U) throw ArchiveError("archive reserved header bits are non-zero");
    result.header.cookie_count=reader.u32();
    if (result.header.cookie_count>limits.maximum_cookies) throw ArchiveError("archive cookie count exceeds configured limit");
    result.header.payload_bytes=reader.u64(); result.header.checksum=reader.u64();
    if (result.header.payload_bytes>reader.remaining()) throw ArchiveError("archive payload length exceeds remaining input");
    const auto payload=reader.take(static_cast<std::size_t>(result.header.payload_bytes));
    if (archive_checksum(payload)!=result.header.checksum) throw ArchiveError("archive checksum mismatch");
    Reader payload_reader(payload);
    result.cookies.reserve(result.header.cookie_count);
    for (std::uint32_t index=0U;index<result.header.cookie_count;index+=1U) result.cookies.push_back(decode_cookie(payload_reader,limits));
    if (payload_reader.remaining()!=0U) throw ArchiveError("archive payload contains unconsumed bytes");
    result.trailing_bytes=reader.remaining();
    return result;
}

std::uint64_t archive_checksum(std::span<const std::byte> input) noexcept {
    std::uint64_t hash=UINT64_C(0xcbf29ce484222325);
    for (const auto byte:input) { hash^=std::to_integer<std::uint64_t>(byte); hash*=UINT64_C(0x100000001b3); }
    return hash;
}

}
