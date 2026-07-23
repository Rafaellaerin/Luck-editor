#include "luck/domain_index.hpp"
#include <algorithm>

namespace luck {
DomainIndex::DomainIndex(const std::vector<Cookie>& cookies){ rebuild(cookies); }

void DomainIndex::insert(const Cookie& cookie) {
    const auto labels=reversed_domain_labels(cookie.domain);
    auto* node=walk_or_create(root_,labels);
    const bool was_empty=node->exact_keys.empty();
    const auto [iterator,inserted]=node->exact_keys.insert(cookie.key());
    (void)iterator;
    if (inserted) { key_count_+=1U; if (was_empty) domain_count_+=1U; }
}

void DomainIndex::erase(const Cookie& cookie) {
    const auto labels=reversed_domain_labels(cookie.domain);
    const auto* existing=walk(root_,labels);
    if (existing==nullptr) return;
    auto* node=walk_or_create(root_,labels);
    if (node->exact_keys.erase(cookie.key())==0U) return;
    key_count_-=1U;
    if (node->exact_keys.empty()) domain_count_-=1U;
    (void)prune(root_,labels,0U);
}

void DomainIndex::rebuild(const std::vector<Cookie>& cookies){ clear(); for (const auto& cookie:cookies) insert(cookie); }
void DomainIndex::clear(){ root_=Node{}; domain_count_=0U; key_count_=0U; }

std::vector<CookieKey> DomainIndex::exact(std::string_view domain) const {
    const auto* node=walk(root_,reversed_domain_labels(domain));
    return node==nullptr?std::vector<CookieKey>{}:std::vector<CookieKey>{node->exact_keys.begin(),node->exact_keys.end()};
}

std::vector<CookieKey> DomainIndex::matching(std::string_view hostname) const {
    const auto labels=reversed_domain_labels(hostname);
    const Node* node=&root_;
    std::set<CookieKey> keys;
    for (const auto& label:labels) {
        const auto iterator=node->children.find(label);
        if (iterator==node->children.end()) break;
        node=&iterator->second;
        keys.insert(node->exact_keys.begin(),node->exact_keys.end());
    }
    return {keys.begin(),keys.end()};
}

std::vector<std::string> DomainIndex::domains() const {
    std::vector<std::string> labels;
    std::vector<std::string> output;
    collect_domains(root_,labels,output);
    std::sort(output.begin(),output.end());
    return output;
}

std::size_t DomainIndex::domain_count() const noexcept{return domain_count_;}
std::size_t DomainIndex::key_count() const noexcept{return key_count_;}

const DomainIndex::Node* DomainIndex::walk(const Node& root,const std::vector<std::string>& labels) {
    const Node* node=&root;
    for (const auto& label:labels) {
        const auto iterator=node->children.find(label);
        if (iterator==node->children.end()) return nullptr;
        node=&iterator->second;
    }
    return node;
}

DomainIndex::Node* DomainIndex::walk_or_create(Node& root,const std::vector<std::string>& labels) {
    Node* node=&root;
    for (const auto& label:labels) node=&node->children[label];
    return node;
}

bool DomainIndex::prune(Node& node,const std::vector<std::string>& labels,std::size_t position) {
    if (position<labels.size()) {
        const auto iterator=node.children.find(labels[position]);
        if (iterator!=node.children.end() && prune(iterator->second,labels,position+1U)) node.children.erase(iterator);
    }
    return node.children.empty()&&node.exact_keys.empty();
}

void DomainIndex::collect_domains(const Node& node,std::vector<std::string>& labels,std::vector<std::string>& output) {
    if (!node.exact_keys.empty()) {
        std::string domain;
        for (auto iterator=labels.rbegin(); iterator!=labels.rend(); ++iterator) { if (!domain.empty()) domain.push_back('.'); domain+=*iterator; }
        output.push_back(std::move(domain));
    }
    for (const auto& [label,child]:node.children) { labels.push_back(label); collect_domains(child,labels,output); labels.pop_back(); }
}
}
