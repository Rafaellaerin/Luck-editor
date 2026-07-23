#include "luck/store.hpp"
#include <algorithm>
#include <cctype>
#include <mutex>
#include <stdexcept>
#include <utility>

namespace luck {

bool Cookie::domain_matches(std::string_view hostname) const {
    const auto cookie_domain=normalized_domain(domain);
    const auto host=normalized_domain(hostname);
    if (cookie_domain==host) return true;
    return host.size()>cookie_domain.size() && host.ends_with(cookie_domain) && host[host.size()-cookie_domain.size()-1U]=='.';
}

bool Cookie::path_matches(std::string_view request_path) const {
    const std::string_view cookie_path=path.empty()?std::string_view{"/"}:std::string_view{path};
    if (request_path==cookie_path) return true;
    if (!request_path.starts_with(cookie_path)) return false;
    return cookie_path.ends_with('/') || (request_path.size()>cookie_path.size() && request_path[cookie_path.size()]=='/');
}

Cookie Cookie::from_c(const luck_cookie& source) {
    Cookie cookie;
    cookie.name=source.name; cookie.value=source.value; cookie.domain=source.domain; cookie.path=source.path;
    cookie.store_id=source.store_id; cookie.partition_site=source.partition_site;
    if (!source.session && source.expiration_date>0.0) cookie.expiration_date=source.expiration_date;
    switch (source.same_site) {
        case LUCK_SAME_SITE_NONE: cookie.same_site=SameSite::none; break;
        case LUCK_SAME_SITE_LAX: cookie.same_site=SameSite::lax; break;
        case LUCK_SAME_SITE_STRICT: cookie.same_site=SameSite::strict; break;
        case LUCK_SAME_SITE_UNSPECIFIED: cookie.same_site=SameSite::unspecified; break;
        default: cookie.same_site=SameSite::unspecified; break;
    }
    cookie.secure=source.secure; cookie.http_only=source.http_only; cookie.session=source.session;
    cookie.host_only=source.host_only; cookie.partitioned=source.partitioned;
    return cookie;
}

luck_cookie Cookie::to_c() const {
    luck_cookie target;
    luck_cookie_init(&target);
    if (luck_cookie_set_name(&target,luck_sv_n(name.data(),name.size()))!=LUCK_OK ||
        luck_cookie_set_value(&target,luck_sv_n(value.data(),value.size()))!=LUCK_OK ||
        luck_cookie_set_domain(&target,luck_sv_n(domain.data(),domain.size()))!=LUCK_OK ||
        luck_cookie_set_path(&target,luck_sv_n(path.data(),path.size()))!=LUCK_OK ||
        luck_cookie_set_store_id(&target,luck_sv_n(store_id.data(),store_id.size()))!=LUCK_OK ||
        luck_cookie_set_partition_site(&target,luck_sv_n(partition_site.data(),partition_site.size()))!=LUCK_OK)
        throw std::length_error("cookie field exceeds C ABI capacity");
    target.expiration_date=expiration_date.value_or(0.0);
    target.same_site=same_site==SameSite::none?LUCK_SAME_SITE_NONE:same_site==SameSite::lax?LUCK_SAME_SITE_LAX:
                     same_site==SameSite::strict?LUCK_SAME_SITE_STRICT:LUCK_SAME_SITE_UNSPECIFIED;
    target.secure=secure; target.http_only=http_only; target.session=effective_session();
    target.host_only=host_only; target.partitioned=partitioned;
    return target;
}

std::string ascii_lower(std::string_view value) {
    std::string result(value);
    std::transform(result.begin(),result.end(),result.begin(),[](unsigned char character){ return static_cast<char>(std::tolower(character)); });
    return result;
}

std::string normalized_domain(std::string_view value) {
    while (!value.empty() && (value.front()=='.' || std::isspace(static_cast<unsigned char>(value.front()))!=0)) value.remove_prefix(1U);
    while (!value.empty() && (value.back()=='.' || std::isspace(static_cast<unsigned char>(value.back()))!=0)) value.remove_suffix(1U);
    return ascii_lower(value);
}

std::vector<std::string> reversed_domain_labels(std::string_view domain) {
    const auto normalized=normalized_domain(domain);
    std::vector<std::string> labels;
    std::size_t start=0U;
    while (start<=normalized.size()) {
        const auto end=normalized.find('.',start);
        labels.emplace_back(normalized.substr(start,end==std::string::npos?std::string::npos:end-start));
        if (end==std::string::npos) break;
        start=end+1U;
    }
    std::reverse(labels.begin(),labels.end());
    return labels;
}

std::string same_site_name(SameSite value) {
    switch (value) { case SameSite::none:return "none"; case SameSite::lax:return "lax"; case SameSite::strict:return "strict"; case SameSite::unspecified:return "unspecified"; }
    return "unspecified";
}

SameSite parse_same_site(std::string_view value) {
    const auto normalized=ascii_lower(value);
    if (normalized=="none" || normalized=="no_restriction") return SameSite::none;
    if (normalized=="lax") return SameSite::lax;
    if (normalized=="strict") return SameSite::strict;
    return SameSite::unspecified;
}

CookieStore::CookieStore(std::vector<Cookie> cookies) { for (auto& cookie:cookies) upsert(std::move(cookie)); }
std::size_t CookieStore::size() const { std::shared_lock lock(mutex_); return cookies_.size(); }
bool CookieStore::empty() const { return size()==0U; }
std::uint64_t CookieStore::version() const { std::shared_lock lock(mutex_); return version_; }

std::optional<CookieStore::VersionedCookie> CookieStore::get(const CookieKey& key) const {
    std::shared_lock lock(mutex_);
    const auto iterator=cookies_.find(key);
    return iterator==cookies_.end()?std::nullopt:std::optional<VersionedCookie>{iterator->second};
}

std::vector<Cookie> CookieStore::all() const {
    std::shared_lock lock(mutex_);
    std::vector<Cookie> result;
    result.reserve(cookies_.size());
    for (const auto& [key,value]:cookies_) { (void)key; result.push_back(value.cookie); }
    std::sort(result.begin(),result.end(),[](const Cookie& left,const Cookie& right){ return left.key()<right.key(); });
    return result;
}

std::vector<Cookie> CookieStore::find(const Predicate& predicate) const {
    std::shared_lock lock(mutex_);
    std::vector<Cookie> result;
    for (const auto& [key,value]:cookies_) { (void)key; if (predicate(value.cookie)) result.push_back(value.cookie); }
    return result;
}

std::vector<Cookie> CookieStore::for_domain(std::string_view hostname) const {
    return find([hostname](const Cookie& cookie){ return cookie.domain_matches(hostname); });
}

CookieStore::MutationResult CookieStore::upsert(Cookie cookie) {
    std::unique_lock lock(mutex_);
    const auto key=cookie.key();
    const auto iterator=cookies_.find(key);
    version_+=1U;
    if (iterator==cookies_.end()) { cookies_.emplace(key,VersionedCookie{std::move(cookie),version_}); return {true,false,version_}; }
    iterator->second=VersionedCookie{std::move(cookie),version_};
    return {false,true,version_};
}

bool CookieStore::erase(const CookieKey& key) {
    std::unique_lock lock(mutex_);
    if (cookies_.erase(key)==0U) return false;
    version_+=1U;
    return true;
}

std::size_t CookieStore::erase_if(const Predicate& predicate) {
    std::unique_lock lock(mutex_);
    std::size_t removed=0U;
    for (auto iterator=cookies_.begin(); iterator!=cookies_.end();) {
        if (predicate(iterator->second.cookie)) { iterator=cookies_.erase(iterator); removed+=1U; } else ++iterator;
    }
    if (removed>0U) version_+=1U;
    return removed;
}

void CookieStore::clear() {
    std::unique_lock lock(mutex_);
    if (!cookies_.empty()) { cookies_.clear(); version_+=1U; }
}

CookieStore::Transaction::Transaction(CookieStore& store):store_(&store),base_version_(store.version()){}
CookieStore::Transaction::~Transaction(){ if (!finished_) rollback(); }
void CookieStore::Transaction::upsert(Cookie cookie){ if (finished_) throw std::logic_error("transaction already finished"); operations_.push_back({Operation::Type::upsert,std::move(cookie),{}}); }
void CookieStore::Transaction::erase(CookieKey key){ if (finished_) throw std::logic_error("transaction already finished"); operations_.push_back({Operation::Type::erase,{},std::move(key)}); }

bool CookieStore::Transaction::commit() {
    if (finished_ || store_==nullptr) return false;
    std::unique_lock lock(store_->mutex_);
    if (store_->version_!=base_version_) { finished_=true; return false; }
    for (auto& operation:operations_) {
        if (operation.type==Operation::Type::upsert) {
            const auto key=operation.cookie.key();
            store_->version_+=1U;
            store_->cookies_.insert_or_assign(key,VersionedCookie{std::move(operation.cookie),store_->version_});
        } else if (store_->cookies_.erase(operation.key)!=0U) store_->version_+=1U;
    }
    finished_=true;
    return true;
}

void CookieStore::Transaction::rollback() noexcept { operations_.clear(); finished_=true; }

}
