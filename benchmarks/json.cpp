#include "control/types.hpp"
#include <chrono>
#include <iostream>

using namespace control;
int main(int argc, char **argv) {
    select_json_backend(argc > 1 ? argv[1] : "auto");
    unsigned iterations = argc > 2 ? unsigned(std::stoul(argv[2])) : 100000;
    Json records = Json::array();
    for (int i = 0; i < 32; ++i)
        records.push_back({{"node_id", "n_" + std::to_string(i)},
                           {"region", "cn-south"},
                           {"operator", "telecom"},
                           {"rtt_ms", 17 + i},
                           {"slots", 512},
                           {"bandwidth", 1000000000}});
    auto input = Json({{"nodes", records}, {"sequence", 1234}, {"protocol", 1}}).dump();
    std::uint64_t checksum = 0;
    for (unsigned i = 0; i < 1000; ++i)
        checksum += parse_json(input)["nodes"].size();
    auto start = std::chrono::steady_clock::now();
    for (unsigned i = 0; i < iterations; ++i)
        checksum += parse_json(input)["nodes"].size();
    auto seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
    std::cout << Json({{"benchmark", "JSON parse plus domain materialization"},
                       {"backend", json_backend()},
                       {"iterations", iterations},
                       {"bytes", input.size()},
                       {"seconds", seconds},
                       {"operations_per_second", iterations / seconds},
                       {"checksum", checksum}})
                     .dump()
              << '\n';
}
