#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
#include "luck/archive.hpp"
#include "luck/diff.hpp"
#include "luck/domain_index.hpp"
#include "luck/policy.hpp"
#include "luck/query.hpp"
#include "luck/snapshot.hpp"
#include "luck/statistics.hpp"
#include "luck/store.hpp"

namespace {
int failures=0;
#define CHECK(condition) do { if (!(condition)) { std::cerr<<"FAIL "<<__FILE__<<':'<<__LINE__<<": "<<#condition<<'\n'; failures+=1; } } while (false)

luck::Cookie cookie(std::string name,std::string domain,bool secure=true) {
    luck::Cookie value; value.name=std::move(name); value.value="secret"; value.domain=std::move(domain);
    value.secure=secure; value.http_only=true; value.same_site=luck::SameSite::lax; return value;
}

void test_store() {
    luck::CookieStore store;
    auto a=cookie("a","example.com");
    CHECK(store.upsert(a).inserted); CHECK(store.size()==1U);
    a.value="changed"; CHECK(store.upsert(a).replaced); CHECK(store.get(a.key())->cookie.value=="changed");
    CHECK(store.for_domain("api.example.com").size()==1U); CHECK(store.erase(a.key())); CHECK(store.empty());
}

void test_transaction_conflict() {
    luck::CookieStore store; store.upsert(cookie("a","example.com"));
    luck::CookieStore::Transaction transaction(store); transaction.upsert(cookie("b","example.com"));
    store.upsert(cookie("c","example.com")); CHECK(!transaction.commit()); CHECK(store.size()==2U);
}

void test_domain_index() {
    std::vector<luck::Cookie> cookies{cookie("a","example.com"),cookie("b",".example.com"),cookie("c","other.test")};
    luck::DomainIndex index(cookies);
    CHECK(index.domain_count()==2U); CHECK(index.key_count()==3U);
    CHECK(index.matching("api.example.com").size()==2U); CHECK(index.exact("other.test").size()==1U);
}

void test_query() {
    std::vector<luck::Cookie> cookies{cookie("session","example.com",true),cookie("theme","example.com",true),cookie("session","other.test",false)};
    CHECK(luck::Query::parse("name:session and secure:true").execute(cookies).size()==1U);
    CHECK(luck::Query::parse("(domain:example.com or domain:other.test) and not secure:false").execute(cookies).size()==2U);
}

void test_diff() {
    auto original=cookie("a","example.com"); auto changed=original; changed.value="new";
    const auto diff=luck::diff_cookies({original},{changed,cookie("b","example.com")});
    CHECK(diff.added.size()==1U); CHECK(diff.changed.size()==1U); CHECK(diff.total_changes()==2U);
    const auto applied=luck::apply_diff({original},diff); CHECK(applied.size()==2U);
    CHECK(luck::apply_diff(applied,luck::invert_diff(diff)).size()==1U);
}

void test_snapshots() {
    luck::SnapshotManager manager(2U,10U);
    const auto first=manager.create("before","example.com",{cookie("a","example.com")},false).id;
    auto changed=cookie("a","example.com"); changed.value="new";
    const auto second=manager.create("after","example.com",{changed},false).id;
    CHECK(manager.size()==2U); CHECK(manager.compare(first,second).changed.size()==1U);
    CHECK(manager.get(second)->fingerprint.size()==64U);
}

void test_policy() {
    auto insecure=cookie("session_token","example.com",false); insecure.http_only=false;
    luck::CookiePolicyConfig secure_config; secure_config.require_secure=true;
    luck::CookiePolicy policy(secure_config);
    const auto decision=policy.evaluate(insecure,1000.0);
    CHECK(!decision.allowed()); CHECK(decision.count(luck::RiskLevel::high)>=1U);
    auto safe=cookie("theme","example.com",true); safe.http_only=true;
    luck::CookiePolicyConfig allow_config; allow_config.allowed_domains={"example.com"};
    luck::CookiePolicy allow_policy(allow_config);
    CHECK(allow_policy.evaluate(safe,1000.0).allowed());
}

void test_archive() {
    auto first=cookie("session","example.com"); first.value="secret"; first.expiration_date=2000000000.0; first.session=false;
    auto second=cookie("theme",".example.com"); second.same_site=luck::SameSite::strict; second.partitioned=true;
    const auto encoded=luck::encode_archive({first,second});
    const auto decoded=luck::decode_archive(encoded);
    CHECK(decoded.cookies.size()==2U); CHECK(decoded.cookies[0].value=="secret"); CHECK(decoded.cookies[1].partitioned);
    auto corrupted=encoded; corrupted.back()^=std::byte{0xffU};
    bool rejected=false; try { (void)luck::decode_archive(corrupted); } catch (const luck::ArchiveError&) { rejected=true; }
    CHECK(rejected);
}

void test_statistics() {
    auto first=cookie("a","example.com"); auto second=cookie("b","example.com",false); second.http_only=false;
    const auto statistics=luck::calculate_statistics({first,second});
    CHECK(statistics.total==2U); CHECK(statistics.secure==1U); CHECK(statistics.by_domain.at("example.com")==2U);
    CHECK(!statistics.largest_cookies.empty());
}
}

int main() {
    try { test_store(); test_transaction_conflict(); test_domain_index(); test_query(); test_diff(); test_snapshots(); test_policy(); test_archive(); test_statistics(); }
    catch (const std::exception& error) { std::cerr<<"unexpected exception: "<<error.what()<<'\n'; return EXIT_FAILURE; }
    if (failures!=0) { std::cerr<<failures<<" native C++ tests failed\n"; return EXIT_FAILURE; }
    std::cout<<"all native C++ tests passed\n"; return EXIT_SUCCESS;
}
