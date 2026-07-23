#ifndef LUCK_CPP_STATISTICS_HPP
#define LUCK_CPP_STATISTICS_HPP
#include <cstddef>
#include <map>
#include <string>
#include <utility>
#include <vector>
#include "luck/model.hpp"
namespace luck {
struct CookieStatistics {
    std::size_t total{0}; std::size_t secure{0}; std::size_t http_only{0}; std::size_t session{0};
    std::size_t persistent{0}; std::size_t host_only{0}; std::size_t partitioned{0}; std::size_t expired{0};
    std::size_t total_bytes{0}; std::size_t maximum_cookie_bytes{0}; double average_cookie_bytes{0.0};
    std::map<std::string,std::size_t> by_domain; std::map<std::string,std::size_t> by_same_site;
    std::vector<std::pair<std::string,std::size_t>> largest_cookies;
};
CookieStatistics calculate_statistics(const std::vector<Cookie>& cookies,std::size_t largest_limit=10U);
}
#endif
