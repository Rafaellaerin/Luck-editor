#ifndef LUCK_CPP_DIFF_HPP
#define LUCK_CPP_DIFF_HPP
#include <vector>
#include "luck/model.hpp"
namespace luck {
struct CookieChange { CookieKey key; Cookie before; Cookie after; std::vector<std::string> changed_fields; };
struct CookieDiff {
    std::vector<Cookie> added; std::vector<Cookie> removed; std::vector<CookieChange> changed;
    [[nodiscard]] bool empty() const noexcept { return added.empty()&&removed.empty()&&changed.empty(); }
    [[nodiscard]] std::size_t total_changes() const noexcept { return added.size()+removed.size()+changed.size(); }
};
CookieDiff diff_cookies(const std::vector<Cookie>& before,const std::vector<Cookie>& after);
std::vector<Cookie> apply_diff(const std::vector<Cookie>& base,const CookieDiff& diff);
CookieDiff invert_diff(const CookieDiff& diff);
}
#endif
