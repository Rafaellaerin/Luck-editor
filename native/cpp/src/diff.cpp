#include "luck/diff.hpp"
#include <algorithm>
#include <unordered_map>

namespace luck {
namespace {
using Map=std::unordered_map<CookieKey,Cookie,CookieKeyHash>;
Map to_map(const std::vector<Cookie>& cookies){ Map result; for (const auto& cookie:cookies) result.insert_or_assign(cookie.key(),cookie); return result; }
std::vector<std::string> changed_fields(const Cookie& before,const Cookie& after) {
    std::vector<std::string> fields;
    if (before.value!=after.value) fields.emplace_back("value");
    if (before.secure!=after.secure) fields.emplace_back("secure");
    if (before.http_only!=after.http_only) fields.emplace_back("http_only");
    if (before.same_site!=after.same_site) fields.emplace_back("same_site");
    if (before.expiration_date!=after.expiration_date) fields.emplace_back("expiration_date");
    if (before.session!=after.session) fields.emplace_back("session");
    if (before.host_only!=after.host_only) fields.emplace_back("host_only");
    if (before.partitioned!=after.partitioned) fields.emplace_back("partitioned");
    return fields;
}
}

CookieDiff diff_cookies(const std::vector<Cookie>& before,const std::vector<Cookie>& after) {
    const auto before_map=to_map(before);
    const auto after_map=to_map(after);
    CookieDiff diff;
    for (const auto& [key,cookie]:after_map) {
        const auto iterator=before_map.find(key);
        if (iterator==before_map.end()) diff.added.push_back(cookie);
        else {
            auto fields=changed_fields(iterator->second,cookie);
            if (!fields.empty()) diff.changed.push_back({key,iterator->second,cookie,std::move(fields)});
        }
    }
    for (const auto& [key,cookie]:before_map) if (!after_map.contains(key)) diff.removed.push_back(cookie);
    const auto order=[](const Cookie& left,const Cookie& right){ return left.key()<right.key(); };
    std::sort(diff.added.begin(),diff.added.end(),order);
    std::sort(diff.removed.begin(),diff.removed.end(),order);
    std::sort(diff.changed.begin(),diff.changed.end(),[](const CookieChange& left,const CookieChange& right){ return left.key<right.key; });
    return diff;
}

std::vector<Cookie> apply_diff(const std::vector<Cookie>& base,const CookieDiff& diff) {
    auto map=to_map(base);
    for (const auto& cookie:diff.removed) map.erase(cookie.key());
    for (const auto& change:diff.changed) map.insert_or_assign(change.key,change.after);
    for (const auto& cookie:diff.added) map.insert_or_assign(cookie.key(),cookie);
    std::vector<Cookie> result;
    result.reserve(map.size());
    for (auto& [key,cookie]:map) { (void)key; result.push_back(std::move(cookie)); }
    std::sort(result.begin(),result.end(),[](const Cookie& left,const Cookie& right){ return left.key()<right.key(); });
    return result;
}

CookieDiff invert_diff(const CookieDiff& diff) {
    CookieDiff inverse;
    inverse.added=diff.removed; inverse.removed=diff.added;
    for (const auto& change:diff.changed) inverse.changed.push_back({change.key,change.after,change.before,change.changed_fields});
    return inverse;
}
}
