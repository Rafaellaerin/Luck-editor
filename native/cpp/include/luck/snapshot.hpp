#ifndef LUCK_CPP_SNAPSHOT_HPP
#define LUCK_CPP_SNAPSHOT_HPP
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <optional>
#include <string>
#include <vector>
#include "luck/diff.hpp"
namespace luck {
struct Snapshot {
    std::uint64_t id{0}; std::string name; std::string domain;
    std::chrono::system_clock::time_point created_at; std::vector<Cookie> cookies;
    std::string fingerprint; bool redacted{true};
};
class SnapshotManager {
public:
    explicit SnapshotManager(std::size_t maximum_snapshots=20U,std::size_t maximum_cookies=2000U);
    const Snapshot& create(std::string name,std::string domain,std::vector<Cookie> cookies,bool redact_values=true);
    bool erase(std::uint64_t id); void clear();
    [[nodiscard]] std::optional<Snapshot> get(std::uint64_t id) const;
    [[nodiscard]] std::vector<Snapshot> list() const;
    [[nodiscard]] CookieDiff compare(std::uint64_t older_id,std::uint64_t newer_id) const;
    [[nodiscard]] std::size_t size() const noexcept;
private:
    std::size_t maximum_snapshots_; std::size_t maximum_cookies_; std::uint64_t next_id_{1}; std::deque<Snapshot> snapshots_;
};
}
#endif
