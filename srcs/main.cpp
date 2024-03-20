
#include "Client.hpp"
#include "Server.hpp"
#include "Channel.hpp"

int main (int argc, char **argv)
{
    Server server;

    if (!server.checkAndSetArgv(argc, argv))
    {
        server.printUsage(argv);
        exit(1);
    }

    server.init_server();

    

    return 0;
}