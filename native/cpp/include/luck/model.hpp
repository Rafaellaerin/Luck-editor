#ifndef LUCK_CPP_MODEL_HPP
#define LUCK_CPP_MODEL_HPP
#include <algorithm>
#include <compare>
#include <cstddef>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>
extern "C" {
#include "luck/cookie.h"
}
namespace luck {
enum class SameSite { unspecified, none, lax, strict };
struct CookieKey {
    std::string store_id; std::string partition_site; std::string domain; std::string path; std::string name;
    auto operator<=>(const CookieKey&) const = default;
};
struct Cookie {
    std::string name; std::string value; std::string domain; std::string path{"/"};
    std::string store_id; std::string partition_site; std::optional<double> expiration_date;
    SameSite same_site{SameSite::unspecified}; bool secure{false}; bool http_only{false};
    bool session{true}; bool host_only{true}; bool partitioned{false};
    [[nodiscard]] CookieKey key() const { return {store_id, partition_site, domain, path, name}; }
    [[nodiscard]] std::size_t estimated_bytes() const noexcept { return name.size()+value.size()+domain.size()+path.size()+store_id.size()+partition_site.size(); }
    [[nodiscard]] bool expired_at(double unix_seconds) const noexcept { return expiration_date.has_value() && *expiration_date <= unix_seconds; }
    [[nodiscard]] bool effective_session() const noexcept { return session || !expiration_date.has_value(); }
    [[nodiscard]] bool domain_matches(std::string_view hostname) const;
    [[nodiscard]] bool path_matches(std::string_view request_path) const;
    static Cookie from_c(const luck_cookie& source);
    [[nodiscard]] luck_cookie to_c() const;
};
struct CookieKeyHash {
    std::size_t operator()(const CookieKey& key) const noexcept {
        std::size_t seed=0U;
        const auto combine=[&seed](std::string_view value) {
            const auto hash=std::hash<std::string_view>{}(value);
            seed ^= hash + static_cast<std::size_t>(0x9e3779b9U) + (seed<<6U) + (seed>>2U);
        };
        combine(key.store_id); combine(key.partition_site); combine(key.domain); combine(key.path); combine(key.name);
        return seed;
    }
};
std::string ascii_lower(std::string_view value);
std::string normalized_domain(std::string_view value);
std::vector<std::string> reversed_domain_labels(std::string_view domain);
std::string same_site_name(SameSite value);
SameSite parse_same_site(std::string_view value);
}
#endif
