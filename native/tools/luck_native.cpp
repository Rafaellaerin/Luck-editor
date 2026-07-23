#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>
extern "C" {
#include "luck/buffer.h"
#include "luck/parser.h"
#include "luck/serialize.h"
}
#include "luck/statistics.hpp"
namespace {
std::string read_all(const char* path) {
    if (path==nullptr || std::string_view(path)=="-") return {std::istreambuf_iterator<char>(std::cin),std::istreambuf_iterator<char>()};
    std::ifstream stream(path,std::ios::binary);
    if (!stream) throw std::runtime_error("cannot open input file");
    return {std::istreambuf_iterator<char>(stream),std::istreambuf_iterator<char>()};
}
}
int main(int argc,char** argv) {
    if (argc<2 || argc>3) { std::cerr<<"usage: luck-native <fallback-domain> [file|-]\n"; return 2; }
    try {
        const auto input=read_all(argc==3?argv[2]:"-");
        luck_cookie_collection collection; luck_cookie_collection_init(&collection);
        luck_parse_report report{}; auto options=luck_parse_options_default(); options.fallback_domain=argv[1];
        const auto status=luck_parse_cookies(luck_sv_n(input.data(),input.size()),&options,&collection,&report);
        if (status!=LUCK_OK) { std::cerr<<"parse failed: "<<luck_status_message(status)<<'\n'; luck_cookie_collection_destroy(&collection); return 1; }
        std::vector<luck::Cookie> cookies; cookies.reserve(collection.length);
        for (std::size_t index=0U; index<collection.length; index+=1U) cookies.push_back(luck::Cookie::from_c(collection.items[index]));
        const auto statistics=luck::calculate_statistics(cookies);
        std::cerr<<"accepted="<<statistics.total<<" secure="<<statistics.secure<<" http_only="<<statistics.http_only<<'\n';
        luck_buffer output; luck_buffer_init(&output); auto serialize_options=luck_serialize_options_default(); serialize_options.include_http_only=true;
        if (luck_serialize_cookies(&collection,&serialize_options,&output)!=LUCK_OK) { luck_buffer_destroy(&output); luck_cookie_collection_destroy(&collection); return 1; }
        std::cout<<output.data;
        luck_buffer_destroy(&output); luck_cookie_collection_destroy(&collection); return 0;
    } catch (const std::exception& error) { std::cerr<<"luck-native: "<<error.what()<<'\n'; return 1; }
}
