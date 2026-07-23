#ifndef LUCK_CPP_STORE_HPP
#define LUCK_CPP_STORE_HPP
#include <cstdint>
#include <functional>
#include <optional>
#include <shared_mutex>
#include <unordered_map>
#include <vector>
#include "luck/model.hpp"
namespace luck {
class CookieStore {
public:
    using Predicate=std::function<bool(const Cookie&)>;
    struct VersionedCookie { Cookie cookie; std::uint64_t version; };
    struct MutationResult { bool inserted{false}; bool replaced{false}; std::uint64_t version{0}; };
    CookieStore()=default;
    explicit CookieStore(std::vector<Cookie> cookies);
    [[nodiscard]] std::size_t size() const;
    [[nodiscard]] bool empty() const;
    [[nodiscard]] std::uint64_t version() const;
    [[nodiscard]] std::optional<VersionedCookie> get(const CookieKey& key) const;
    [[nodiscard]] std::vector<Cookie> all() const;
    [[nodiscard]] std::vector<Cookie> find(const Predicate& predicate) const;
    [[nodiscard]] std::vector<Cookie> for_domain(std::string_view hostname) const;
    MutationResult upsert(Cookie cookie);
    bool erase(const CookieKey& key);
    std::size_t erase_if(const Predicate& predicate);
    void clear();
    class Transaction {
    public:
        explicit Transaction(CookieStore& store);
        Transaction(const Transaction&)=delete; Transaction& operator=(const Transaction&)=delete;
        Transaction(Transaction&&)=delete; Transaction& operator=(Transaction&&)=delete;
        ~Transaction();
        void upsert(Cookie cookie); void erase(CookieKey key);
        [[nodiscard]] bool commit(); void rollback() noexcept;
    private:
        struct Operation { enum class Type { upsert, erase } type; Cookie cookie; CookieKey key; };
        CookieStore* store_; std::uint64_t base_version_; std::vector<Operation> operations_; bool finished_{false};
    };
private:
    friend class Transaction;
    mutable std::shared_mutex mutex_;
    std::unordered_map<CookieKey,VersionedCookie,CookieKeyHash> cookies_;
    std::uint64_t version_{0};
};
}
#endif
