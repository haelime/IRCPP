
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

    Logger::setConsoleLogging(true);
    Logger::setFileLogging("log.txt");
    Logger::setLogLevelLimit(INFO);

    server.init_server();
    server.run();

    // Logger::closeFileLogging();

    return 0;
}