#include "luck/policy.hpp"
#include <algorithm>
#include <chrono>
#include <cmath>
#include <utility>

namespace luck {
namespace {

void add_finding(PolicyDecision& decision,std::string rule,std::string message,RiskLevel risk,PolicyAction action) {
    decision.findings.push_back({std::move(rule),std::move(message),risk,action});
    if (action==PolicyAction::deny) decision.action=PolicyAction::deny;
    else if (action==PolicyAction::warn && decision.action==PolicyAction::allow) decision.action=PolicyAction::warn;
}

bool domain_is_within(std::string_view domain,std::string_view suffix) {
    const auto normalized=normalized_domain(domain);
    const auto expected=normalized_domain(suffix);
    if (normalized==expected) return true;
    return normalized.size()>expected.size() && normalized.ends_with(expected) &&
           normalized[normalized.size()-expected.size()-1U]=='.';
}

bool contains_case_insensitive(std::string_view value,std::string_view needle) {
    return ascii_lower(value).find(ascii_lower(needle))!=std::string::npos;
}

bool begins_with_case_sensitive(std::string_view value,std::string_view prefix) {
    return value.size()>=prefix.size() && value.substr(0U,prefix.size())==prefix;
}

double current_unix_seconds() {
    return std::chrono::duration<double>(std::chrono::system_clock::now().time_since_epoch()).count();
}

}

std::size_t PolicyDecision::count(RiskLevel risk) const noexcept {
    return static_cast<std::size_t>(std::count_if(findings.begin(),findings.end(),[risk](const PolicyFinding& finding){ return finding.risk==risk; }));
}

CookiePolicy::CookiePolicy(CookiePolicyConfig config):config_(std::move(config)){}
const CookiePolicyConfig& CookiePolicy::config() const noexcept { return config_; }

PolicyDecision CookiePolicy::evaluate(const Cookie& cookie) const { return evaluate(cookie,current_unix_seconds()); }

PolicyDecision CookiePolicy::evaluate(const Cookie& cookie,double now_unix_seconds) const {
    PolicyDecision decision;
    if (cookie.name.empty()) add_finding(decision,"syntax.name.empty","Cookie name is empty.",RiskLevel::high,PolicyAction::deny);
    if (cookie.domain.empty()) add_finding(decision,"syntax.domain.empty","Cookie domain is empty.",RiskLevel::high,PolicyAction::deny);
    if (cookie.path.empty() || cookie.path.front()!='/') add_finding(decision,"syntax.path.invalid","Cookie path must begin with a slash.",RiskLevel::high,PolicyAction::deny);
    if (cookie.value.find_first_of("\r\n")!=std::string::npos) add_finding(decision,"syntax.value.line_break","Cookie value contains a line break.",RiskLevel::critical,PolicyAction::deny);
    if (cookie.estimated_bytes()>config_.maximum_cookie_bytes) {
        add_finding(decision,"size.maximum","Cookie exceeds the configured byte limit.",RiskLevel::high,PolicyAction::deny);
    }
    if (config_.require_secure && !cookie.secure) add_finding(decision,"security.secure.required","Policy requires Secure.",RiskLevel::high,PolicyAction::deny);
    else if (!cookie.secure) add_finding(decision,"security.secure.disabled","Cookie can be sent over an unencrypted connection.",RiskLevel::high,PolicyAction::warn);
    if (!cookie.http_only) add_finding(decision,"security.http_only.disabled","Cookie can be read by page scripts.",RiskLevel::medium,PolicyAction::warn);
    if (cookie.same_site==SameSite::none && !cookie.secure) add_finding(decision,"security.same_site_none_without_secure","SameSite=None requires Secure.",RiskLevel::high,PolicyAction::deny);
    if (config_.deny_same_site_none && cookie.same_site==SameSite::none) add_finding(decision,"policy.same_site_none","Policy denies SameSite=None.",RiskLevel::high,PolicyAction::deny);
    if (cookie.same_site==SameSite::unspecified) add_finding(decision,"security.same_site.unspecified","Browser defaults determine cross-site behavior.",RiskLevel::low,PolicyAction::warn);
    if (config_.deny_session_cookies && cookie.effective_session()) add_finding(decision,"policy.session","Policy denies session cookies.",RiskLevel::medium,PolicyAction::deny);
    if (config_.deny_empty_values && cookie.value.empty()) add_finding(decision,"policy.empty_value","Policy denies empty cookie values.",RiskLevel::medium,PolicyAction::deny);
    if (config_.deny_expired_cookies && cookie.expired_at(now_unix_seconds)) add_finding(decision,"policy.expired","Cookie has already expired.",RiskLevel::medium,PolicyAction::deny);
    if (config_.require_host_only && !cookie.host_only) add_finding(decision,"policy.host_only","Policy requires host-only cookies.",RiskLevel::high,PolicyAction::deny);
    if (cookie.partitioned && !cookie.secure) add_finding(decision,"security.partitioned.secure","Partitioned cookies must be Secure.",RiskLevel::high,PolicyAction::deny);

    if (config_.require_http_only_for_sensitive_names) {
        const auto sensitive=std::any_of(config_.sensitive_name_fragments.begin(),config_.sensitive_name_fragments.end(),
            [&cookie](const std::string& fragment){ return contains_case_insensitive(cookie.name,fragment); });
        if (sensitive && !cookie.http_only) add_finding(decision,"security.sensitive.http_only","Sensitive-looking cookie name is not HttpOnly.",RiskLevel::high,PolicyAction::deny);
    }

    if (config_.require_prefix_compliance) {
        if (begins_with_case_sensitive(cookie.name,"__Secure-") && !cookie.secure)
            add_finding(decision,"prefix.secure","__Secure- cookies must be Secure.",RiskLevel::high,PolicyAction::deny);
        if (begins_with_case_sensitive(cookie.name,"__Host-")) {
            if (!cookie.secure) add_finding(decision,"prefix.host.secure","__Host- cookies must be Secure.",RiskLevel::high,PolicyAction::deny);
            if (cookie.path!="/") add_finding(decision,"prefix.host.path","__Host- cookies must use path /.",RiskLevel::high,PolicyAction::deny);
            if (!cookie.host_only || (!cookie.domain.empty() && cookie.domain.front()=='.'))
                add_finding(decision,"prefix.host.domain","__Host- cookies must be host-only.",RiskLevel::high,PolicyAction::deny);
        }
    }

    for (const auto& prefix:config_.denied_name_prefixes) {
        if (begins_with_case_sensitive(cookie.name,prefix))
            add_finding(decision,"policy.name_prefix","Cookie name uses a denied prefix: "+prefix,RiskLevel::high,PolicyAction::deny);
    }
    for (const auto& suffix:config_.denied_domain_suffixes) {
        if (domain_is_within(cookie.domain,suffix))
            add_finding(decision,"policy.domain.denied","Cookie domain is within a denied suffix: "+suffix,RiskLevel::critical,PolicyAction::deny);
    }
    if (!config_.allowed_domains.empty()) {
        const auto allowed=std::any_of(config_.allowed_domains.begin(),config_.allowed_domains.end(),
            [&cookie](const std::string& domain){ return domain_is_within(cookie.domain,domain); });
        if (!allowed) add_finding(decision,"policy.domain.allowlist","Cookie domain is not in the allowlist.",RiskLevel::critical,PolicyAction::deny);
    }
    if (config_.maximum_lifetime_days.has_value() && cookie.expiration_date.has_value()) {
        const auto lifetime_days=(*cookie.expiration_date-now_unix_seconds)/86400.0;
        if (std::isfinite(lifetime_days) && lifetime_days>*config_.maximum_lifetime_days)
            add_finding(decision,"policy.lifetime","Cookie lifetime exceeds the configured maximum.",RiskLevel::medium,PolicyAction::warn);
    }
    return decision;
}

std::vector<PolicyDecision> CookiePolicy::evaluate(const std::vector<Cookie>& cookies) const {
    std::vector<PolicyDecision> decisions;
    decisions.reserve(cookies.size());
    for (const auto& cookie:cookies) decisions.push_back(evaluate(cookie));
    return decisions;
}

std::vector<Cookie> CookiePolicy::filter_allowed(const std::vector<Cookie>& cookies) const {
    std::vector<Cookie> allowed;
    allowed.reserve(cookies.size());
    for (const auto& cookie:cookies) if (evaluate(cookie).allowed()) allowed.push_back(cookie);
    return allowed;
}

std::string risk_level_name(RiskLevel risk) {
    switch (risk) {
        case RiskLevel::information:return "information";
        case RiskLevel::low:return "low";
        case RiskLevel::medium:return "medium";
        case RiskLevel::high:return "high";
        case RiskLevel::critical:return "critical";
    }
    return "information";
}

std::string policy_action_name(PolicyAction action) {
    switch (action) {
        case PolicyAction::allow:return "allow";
        case PolicyAction::warn:return "warn";
        case PolicyAction::deny:return "deny";
    }
    return "allow";
}

RiskLevel maximum_risk(const PolicyDecision& decision) noexcept {
    RiskLevel result=RiskLevel::information;
    for (const auto& finding:decision.findings) if (finding.risk>result) result=finding.risk;
    return result;
}

}
