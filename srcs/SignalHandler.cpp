#include <csignal>
#include "SignalHandler.hpp"
#include "Logger.hpp"
#include "Server.hpp"
#include "ClientData.hpp"
#include "Channel.hpp"
#include "defines.hpp"

Server* SignalHandler::mServer = NULL;

void SignalHandler::setSignals(Server& server)
{
    SignalHandler::mServer = &server;
    signal(SIGINT, SignalHandler::handleSigInt);
}

void SignalHandler::handleSigInt(int signal)
{
    std::cout << "\nSignal " << signal << " received." << std::endl;


    std::map <SOCKET_FD, ClientData*> fdToClientGlobalMap = SignalHandler::mServer->getFdToClientGlobalMap();
    std::map <std::string, Channel*> nameToChannelGlobalMap = SignalHandler::mServer->getNameToChannelGlobalMap();

    for (std::map<SOCKET_FD, ClientData*>::iterator it = fdToClientGlobalMap.begin(); it != fdToClientGlobalMap.end(); it++)
    {
        close(it->first);
        delete it->second;
    }
    for (std::map<std::string, Channel*>::iterator it = nameToChannelGlobalMap.begin(); it != nameToChannelGlobalMap.end(); it++)
    {
        delete it->second;
    }

    Logger::log(INFO, "Server Got SIGINT. Exiting...");
    exit(0);
}