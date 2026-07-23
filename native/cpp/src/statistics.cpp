#include "luck/statistics.hpp"
#include <algorithm>
#include <chrono>
namespace luck {
CookieStatistics calculate_statistics(const std::vector<Cookie>& cookies,std::size_t largest_limit) {
    CookieStatistics statistics;
    const auto now=std::chrono::duration<double>(std::chrono::system_clock::now().time_since_epoch()).count();
    statistics.total=cookies.size();
    for (const auto& cookie:cookies) {
        const auto bytes=cookie.estimated_bytes();
        statistics.secure+=cookie.secure?1U:0U;
        statistics.http_only+=cookie.http_only?1U:0U;
        statistics.session+=cookie.effective_session()?1U:0U;
        statistics.persistent+=cookie.effective_session()?0U:1U;
        statistics.host_only+=cookie.host_only?1U:0U;
        statistics.partitioned+=cookie.partitioned?1U:0U;
        statistics.expired+=cookie.expired_at(now)?1U:0U;
        statistics.total_bytes+=bytes;
        statistics.maximum_cookie_bytes=std::max(statistics.maximum_cookie_bytes,bytes);
        statistics.by_domain[normalized_domain(cookie.domain)]+=1U;
        statistics.by_same_site[same_site_name(cookie.same_site)]+=1U;
        statistics.largest_cookies.emplace_back(cookie.domain+cookie.path+" :: "+cookie.name,bytes);
    }
    statistics.average_cookie_bytes=statistics.total==0U?0.0:static_cast<double>(statistics.total_bytes)/static_cast<double>(statistics.total);
    std::sort(statistics.largest_cookies.begin(),statistics.largest_cookies.end(),[](const auto& left,const auto& right){ return left.second>right.second; });
    if (statistics.largest_cookies.size()>largest_limit) statistics.largest_cookies.resize(largest_limit);
    return statistics;
}
}
