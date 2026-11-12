#include "control/server.hpp"
#include "control/service.hpp"
#include "control/types.hpp"
#include <iostream>
int main(int argc, char **argv) {
    try {
        if (argc == 2 && std::string_view(argv[1]) == "--version") {
            std::cout << CONTROL_VERSION << '\n';
            return 0;
        }
        if ((argc != 3 && argc != 5) || std::string_view(argv[1]) != "--config" ||
            (argc == 5 && std::string_view(argv[3]) != "--import-browser" && std::string_view(argv[3]) != "--import-social")) {
            std::cerr << "Usage: buggcraft-control --config FILE [--import-browser|--import-social PRIVATE_SNAPSHOT]\n";
            return 2;
        }
        auto config = control::Config::load(argv[2]);
        if (argc == 5) {
            control::Database db(control::read_secret(config.database_file, 16384));
            db.migrate(control::read_file(config.schema_file, 1048576));
            control::Service service(config);
            auto snapshot=control::parse_json(control::read_secret(argv[4],16777216),16777216);
            std::cout << (std::string_view(argv[3])=="--import-social" ? service.import_social(db,snapshot)
                           : service.import_browser(db,snapshot)).dump() << '\n';
            return 0;
        }
        return control::run_server(config);
    } catch (const control::Error &e) {
        std::cerr << e.code << ": " << e.what() << '\n';
    } catch (...) {
        std::cerr << "Service startup failed; check configuration and dependency availability\n";
    }
    return 1;
}
