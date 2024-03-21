
#include "Server.hpp"
#include "ClientData.hpp"
#include "Channel.hpp"

int main (int argc, char **argv)
{
    Server server;

    if (!server.checkAndSetArgv(argc, argv))
    {
        server.printUsage(argv);
        exit(1);
    }

    // Logger::setFileLogging("log.txt");
    Logger::setConsoleLogging(true);

    server.init_server();
    server.run();

    // Logger::closeFileLogging();

    return 0;
}