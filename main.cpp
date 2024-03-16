
#include "Client.hpp"
#include "Server.hpp"

int main (int argc, char**argv)
{
    Server server;

    if (!server.isValidArgv(argc, argv))
    {
        server.printUsage(argv);
        exit(1);
    }
    server.init();

    

    return 0;
}