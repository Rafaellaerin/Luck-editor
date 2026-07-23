#ifndef LUCK_CPP_QUERY_HPP
#define LUCK_CPP_QUERY_HPP
#include <memory>
#include <string_view>
#include <vector>
#include "luck/model.hpp"
namespace luck {
class Query {
public:
    struct Expr;
    Query(); Query(const Query& other); Query& operator=(const Query& other);
    Query(Query&&) noexcept=default; Query& operator=(Query&&) noexcept=default; ~Query();
    [[nodiscard]] static Query parse(std::string_view text);
    [[nodiscard]] bool matches(const Cookie& cookie) const;
    [[nodiscard]] std::vector<Cookie> execute(const std::vector<Cookie>& cookies) const;
private:
    explicit Query(std::unique_ptr<Expr> expression);
    std::unique_ptr<Expr> expression_;
};
}
#endif
