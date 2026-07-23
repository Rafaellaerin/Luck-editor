#ifndef LUCK_CPP_POLICY_HPP
#define LUCK_CPP_POLICY_HPP

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>
#include "luck/model.hpp"

namespace luck {

enum class RiskLevel { information, low, medium, high, critical };
enum class PolicyAction { allow, warn, deny };

struct PolicyFinding {
    std::string rule;
    std::string message;
    RiskLevel risk{RiskLevel::information};
    PolicyAction action{PolicyAction::allow};
};

struct PolicyDecision {
    PolicyAction action{PolicyAction::allow};
    std::vector<PolicyFinding> findings;
    [[nodiscard]] bool allowed() const noexcept { return action!=PolicyAction::deny; }
    [[nodiscard]] std::size_t count(RiskLevel risk) const noexcept;
};

struct CookiePolicyConfig {
    bool require_secure{false};
    bool require_http_only_for_sensitive_names{true};
    bool deny_same_site_none{false};
    bool deny_session_cookies{false};
    bool deny_empty_values{false};
    bool deny_expired_cookies{true};
    bool require_host_only{false};
    bool require_prefix_compliance{true};
    std::size_t maximum_cookie_bytes{4352U};
    std::optional<double> maximum_lifetime_days{400.0};
    std::vector<std::string> allowed_domains;
    std::vector<std::string> denied_domain_suffixes;
    std::vector<std::string> denied_name_prefixes;
    std::vector<std::string> sensitive_name_fragments{"session","auth","token","jwt","bearer"};
};

class CookiePolicy {
public:
    explicit CookiePolicy(CookiePolicyConfig config={});
    [[nodiscard]] const CookiePolicyConfig& config() const noexcept;
    [[nodiscard]] PolicyDecision evaluate(const Cookie& cookie,double now_unix_seconds) const;
    [[nodiscard]] PolicyDecision evaluate(const Cookie& cookie) const;
    [[nodiscard]] std::vector<PolicyDecision> evaluate(const std::vector<Cookie>& cookies) const;
    [[nodiscard]] std::vector<Cookie> filter_allowed(const std::vector<Cookie>& cookies) const;
private:
    CookiePolicyConfig config_;
};

[[nodiscard]] std::string risk_level_name(RiskLevel risk);
[[nodiscard]] std::string policy_action_name(PolicyAction action);
[[nodiscard]] RiskLevel maximum_risk(const PolicyDecision& decision) noexcept;

}
#endif
