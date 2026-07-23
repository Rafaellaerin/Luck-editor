#include "luck/snapshot.hpp"
#include <algorithm>
#include <array>
#include <stdexcept>
extern "C" {
#include "luck/hash.h"
}
namespace luck {
namespace {
std::string fingerprint(const std::vector<Cookie>& cookies) {
    luck_cookie_collection collection;
    luck_cookie_collection_init(&collection);
    try {
        for (const auto& cookie:cookies) {
            const auto native=cookie.to_c();
            if (luck_cookie_collection_push(&collection,&native)!=LUCK_OK) throw std::runtime_error("failed to allocate fingerprint collection");
        }
        std::array<char,LUCK_SHA256_HEX_SIZE> output{};
        if (luck_cookie_fingerprint(&collection,output.data())!=LUCK_OK) throw std::runtime_error("failed to calculate fingerprint");
        luck_cookie_collection_destroy(&collection);
        return output.data();
    } catch (...) {
        luck_cookie_collection_destroy(&collection);
        throw;
    }
}
}
SnapshotManager::SnapshotManager(std::size_t maximum_snapshots,std::size_t maximum_cookies)
    :maximum_snapshots_(std::max<std::size_t>(1U,maximum_snapshots)),maximum_cookies_(std::max<std::size_t>(1U,maximum_cookies)){}

const Snapshot& SnapshotManager::create(std::string name,std::string domain,std::vector<Cookie> cookies,bool redact_values) {
    if (name.empty()) throw std::invalid_argument("snapshot name is required");
    if (cookies.size()>maximum_cookies_) throw std::length_error("snapshot cookie limit exceeded");
    if (redact_values) for (auto& cookie:cookies) cookie.value.clear();
    Snapshot snapshot;
    snapshot.id=next_id_++; snapshot.name=std::move(name); snapshot.domain=normalized_domain(domain);
    snapshot.created_at=std::chrono::system_clock::now(); snapshot.fingerprint=fingerprint(cookies);
    snapshot.cookies=std::move(cookies); snapshot.redacted=redact_values;
    snapshots_.push_front(std::move(snapshot));
    while (snapshots_.size()>maximum_snapshots_) snapshots_.pop_back();
    return snapshots_.front();
}

bool SnapshotManager::erase(std::uint64_t id) {
    const auto iterator=std::find_if(snapshots_.begin(),snapshots_.end(),[id](const Snapshot& snapshot){ return snapshot.id==id; });
    if (iterator==snapshots_.end()) return false;
    snapshots_.erase(iterator);
    return true;
}
void SnapshotManager::clear(){ snapshots_.clear(); }
std::optional<Snapshot> SnapshotManager::get(std::uint64_t id) const {
    const auto iterator=std::find_if(snapshots_.begin(),snapshots_.end(),[id](const Snapshot& snapshot){ return snapshot.id==id; });
    return iterator==snapshots_.end()?std::nullopt:std::optional<Snapshot>{*iterator};
}
std::vector<Snapshot> SnapshotManager::list() const { return {snapshots_.begin(),snapshots_.end()}; }
CookieDiff SnapshotManager::compare(std::uint64_t older_id,std::uint64_t newer_id) const {
    const auto older=get(older_id); const auto newer=get(newer_id);
    if (!older || !newer) throw std::out_of_range("snapshot id not found");
    return diff_cookies(older->cookies,newer->cookies);
}
std::size_t SnapshotManager::size() const noexcept { return snapshots_.size(); }
}
