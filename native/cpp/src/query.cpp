#include "luck/query.hpp"
#include <algorithm>
#include <cctype>
#include <iterator>
#include <memory>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>
#include <variant>

namespace luck {
namespace {
enum class TokenType { word, colon, left_parenthesis, right_parenthesis, logical_and, logical_or, logical_not, end };
struct Token { TokenType type; std::string text; std::size_t offset; };

std::vector<Token> tokenize(std::string_view input) {
    std::vector<Token> tokens;
    std::size_t index=0U;
    while (index<input.size()) {
        const char character=input[index];
        if (std::isspace(static_cast<unsigned char>(character))!=0) { index+=1U; continue; }
        if (character==':') { tokens.push_back({TokenType::colon,":",index++}); continue; }
        if (character=='(') { tokens.push_back({TokenType::left_parenthesis,"(",index++}); continue; }
        if (character==')') { tokens.push_back({TokenType::right_parenthesis,")",index++}); continue; }
        const auto start=index;
        std::string word;
        if (character=='"' || character=='\'') {
            const char quote=character;
            index+=1U;
            bool closed=false;
            while (index<input.size()) {
                const char current=input[index++];
                if (current==quote) { closed=true; break; }
                if (current=='\\' && index<input.size()) word.push_back(input[index++]); else word.push_back(current);
            }
            if (!closed) throw std::invalid_argument("unterminated quoted query value");
        } else {
            while (index<input.size() && std::isspace(static_cast<unsigned char>(input[index]))==0 &&
                   input[index]!=':' && input[index]!='(' && input[index]!=')') word.push_back(input[index++]);
        }
        const auto lower=ascii_lower(word);
        if (lower=="and") tokens.push_back({TokenType::logical_and,word,start});
        else if (lower=="or") tokens.push_back({TokenType::logical_or,word,start});
        else if (lower=="not") tokens.push_back({TokenType::logical_not,word,start});
        else tokens.push_back({TokenType::word,word,start});
    }
    tokens.push_back({TokenType::end,{},input.size()});
    return tokens;
}

bool parse_bool(std::string_view value) {
    const auto lower=ascii_lower(value);
    if (lower=="true" || lower=="yes" || lower=="1") return true;
    if (lower=="false" || lower=="no" || lower=="0") return false;
    throw std::invalid_argument("query boolean must be true or false");
}

bool contains_case_insensitive(std::string_view haystack,std::string_view needle) {
    return ascii_lower(haystack).find(ascii_lower(needle))!=std::string::npos;
}
}

struct Query::Expr {
    struct True {};
    struct Name { std::string value; };
    struct Value { std::string value; };
    struct Domain { std::string value; };
    struct Path { std::string value; };
    struct Secure { bool value; };
    struct HttpOnly { bool value; };
    struct Session { bool value; };
    struct SameSiteValue { SameSite value; };
    struct And { std::vector<Expr> values; };
    struct Or { std::vector<Expr> values; };
    struct Not { std::unique_ptr<Expr> value; };
    using Variant=std::variant<True,Name,Value,Domain,Path,Secure,HttpOnly,Session,SameSiteValue,And,Or,Not>;
    Variant value;

    Expr():value(True{}){}
    explicit Expr(Variant variant):value(std::move(variant)){}
    Expr(const Expr& other):value(clone_variant(other.value)){}
    Expr& operator=(const Expr& other){ if (this!=&other) value=clone_variant(other.value); return *this; }
    Expr(Expr&&) noexcept=default;
    Expr& operator=(Expr&&) noexcept=default;

    [[nodiscard]] bool matches(const Cookie& cookie) const {
        return std::visit([&cookie](const auto& expression)->bool {
            using Type=std::decay_t<decltype(expression)>;
            if constexpr (std::is_same_v<Type,True>) return true;
            else if constexpr (std::is_same_v<Type,Name>) return contains_case_insensitive(cookie.name,expression.value);
            else if constexpr (std::is_same_v<Type,Value>) return contains_case_insensitive(cookie.value,expression.value);
            else if constexpr (std::is_same_v<Type,Domain>) return cookie.domain_matches(expression.value);
            else if constexpr (std::is_same_v<Type,Path>) return cookie.path.starts_with(expression.value);
            else if constexpr (std::is_same_v<Type,Secure>) return cookie.secure==expression.value;
            else if constexpr (std::is_same_v<Type,HttpOnly>) return cookie.http_only==expression.value;
            else if constexpr (std::is_same_v<Type,Session>) return cookie.effective_session()==expression.value;
            else if constexpr (std::is_same_v<Type,SameSiteValue>) return cookie.same_site==expression.value;
            else if constexpr (std::is_same_v<Type,And>) return std::all_of(expression.values.begin(),expression.values.end(),[&cookie](const Expr& child){ return child.matches(cookie); });
            else if constexpr (std::is_same_v<Type,Or>) return std::any_of(expression.values.begin(),expression.values.end(),[&cookie](const Expr& child){ return child.matches(cookie); });
            else if constexpr (std::is_same_v<Type,Not>) return !expression.value->matches(cookie);
            else return false;
        },value);
    }
private:
    static Variant clone_variant(const Variant& source) {
        return std::visit([](const auto& expression)->Variant {
            using Type=std::decay_t<decltype(expression)>;
            if constexpr (std::is_same_v<Type,Not>) return Not{std::make_unique<Expr>(*expression.value)};
            else return expression;
        },source);
    }
};

namespace {
class Parser {
public:
    explicit Parser(std::vector<Token> tokens):tokens_(std::move(tokens)){}
    Query::Expr parse(){ auto expression=parse_or(); expect(TokenType::end,"unexpected trailing query token"); return expression; }
private:
    std::vector<Token> tokens_;
    std::size_t position_{0U};

    Query::Expr parse_or() {
        std::vector<Query::Expr> values;
        values.push_back(parse_and());
        while (consume(TokenType::logical_or)) values.push_back(parse_and());
        if (values.size()==1U) return std::move(values.front());
        return Query::Expr{Query::Expr::Or{std::move(values)}};
    }
    Query::Expr parse_and() {
        std::vector<Query::Expr> values;
        values.push_back(parse_unary());
        while (consume(TokenType::logical_and)) values.push_back(parse_unary());
        if (values.size()==1U) return std::move(values.front());
        return Query::Expr{Query::Expr::And{std::move(values)}};
    }
    Query::Expr parse_unary() {
        if (consume(TokenType::logical_not)) return Query::Expr{Query::Expr::Not{std::make_unique<Query::Expr>(parse_unary())}};
        if (consume(TokenType::left_parenthesis)) {
            auto expression=parse_or();
            expect(TokenType::right_parenthesis,"expected ')' in query");
            return expression;
        }
        return parse_term();
    }
    Query::Expr parse_term() {
        const auto field=take_word();
        if (!consume(TokenType::colon)) {
            std::vector<Query::Expr> values;
            values.emplace_back(Query::Expr::Name{field});
            values.emplace_back(Query::Expr::Domain{field});
            return Query::Expr{Query::Expr::Or{std::move(values)}};
        }
        const auto value=take_word();
        const auto lower=ascii_lower(field);
        if (lower=="name") return Query::Expr{Query::Expr::Name{value}};
        if (lower=="value") return Query::Expr{Query::Expr::Value{value}};
        if (lower=="domain") return Query::Expr{Query::Expr::Domain{value}};
        if (lower=="path") return Query::Expr{Query::Expr::Path{value}};
        if (lower=="secure") return Query::Expr{Query::Expr::Secure{parse_bool(value)}};
        if (lower=="httponly" || lower=="http_only") return Query::Expr{Query::Expr::HttpOnly{parse_bool(value)}};
        if (lower=="session") return Query::Expr{Query::Expr::Session{parse_bool(value)}};
        if (lower=="samesite" || lower=="same_site") return Query::Expr{Query::Expr::SameSiteValue{parse_same_site(value)}};
        throw std::invalid_argument("unknown query field: "+field);
    }
    std::string take_word() {
        if (peek().type!=TokenType::word) throw std::invalid_argument("expected query word at byte "+std::to_string(peek().offset));
        return tokens_[position_++].text;
    }
    bool consume(TokenType type){ if (peek().type==type) { position_+=1U; return true; } return false; }
    void expect(TokenType type,std::string_view message){ if (!consume(type)) throw std::invalid_argument(std::string(message)+" at byte "+std::to_string(peek().offset)); }
    const Token& peek() const { return tokens_[position_]; }
};
}

Query::Query():expression_(std::make_unique<Expr>()){}
Query::Query(std::unique_ptr<Expr> expression):expression_(std::move(expression)){}
Query::Query(const Query& other):expression_(std::make_unique<Expr>(*other.expression_)){}
Query& Query::operator=(const Query& other){ if (this!=&other) expression_=std::make_unique<Expr>(*other.expression_); return *this; }
Query::~Query()=default;
Query Query::parse(std::string_view text){ if (text.empty()) return Query{}; Parser parser(tokenize(text)); return Query(std::make_unique<Expr>(parser.parse())); }
bool Query::matches(const Cookie& cookie) const { return expression_->matches(cookie); }
std::vector<Cookie> Query::execute(const std::vector<Cookie>& cookies) const {
    std::vector<Cookie> result;
    std::copy_if(cookies.begin(),cookies.end(),std::back_inserter(result),[this](const Cookie& cookie){ return matches(cookie); });
    return result;
}
}
