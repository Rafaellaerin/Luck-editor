#ifndef LUCK_CPP_DOMAIN_INDEX_HPP
#define LUCK_CPP_DOMAIN_INDEX_HPP
#include <map>
#include <set>
#include <string>
#include <string_view>
#include <vector>
#include "luck/model.hpp"
namespace luck {
class DomainIndex {
public:
    DomainIndex()=default; explicit DomainIndex(const std::vector<Cookie>& cookies);
    void insert(const Cookie& cookie); void erase(const Cookie& cookie); void rebuild(const std::vector<Cookie>& cookies); void clear();
    [[nodiscard]] std::vector<CookieKey> exact(std::string_view domain) const;
    [[nodiscard]] std::vector<CookieKey> matching(std::string_view hostname) const;
    [[nodiscard]] std::vector<std::string> domains() const;
    [[nodiscard]] std::size_t domain_count() const noexcept; [[nodiscard]] std::size_t key_count() const noexcept;
private:
    struct Node { std::map<std::string,Node,std::less<>> children; std::set<CookieKey> exact_keys; };
    Node root_; std::size_t domain_count_{0}; std::size_t key_count_{0};
    static const Node* walk(const Node& root,const std::vector<std::string>& labels);
    static Node* walk_or_create(Node& root,const std::vector<std::string>& labels);
    static bool prune(Node& node,const std::vector<std::string>& labels,std::size_t position);
    static void collect_domains(const Node& node,std::vector<std::string>& labels,std::vector<std::string>& output);
};
}
#endif
