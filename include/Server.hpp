#pragma once

#include <arpa/inet.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <unistd.h>

#include <iostream>
#include <string>
#include <vector>
#include <utility>

#include "defines.hpp"
#include "ClientData.hpp"
#include "AnsiColorDefines.hpp"
#include "Logger.hpp"

// #include "Channel.hpp"

typedef int SOCKET_FD;
typedef int KQUEUE_FD;

#define SOCKET_ERROR (-1)
#define KQUEUE_ERROR (-1)

class ClientData;
class Channel;

class Server
{
public:
    Server() {};
    ~Server() {};

    void printUsage(char** argv)
    {
        std::cerr << "Usage : " << argv[0] << " <port> <password>\n";
    }
    bool initServer(int argc, char** argv);
    void run();
    void stop() {}; // TODO : implement


private:
    bool setPortAndPassFromArgv(int argc, char** argv);

    // Try parse RecvMsg
    // ClientData Does NOTHING about this recvMsg, only server will handle it.
    bool parseReceivedRequestFromClientData(SOCKET_FD client);

    void sendParsedMessages(ClientData* clientData);
    bool isValidParameter(char c) const;
    bool isValidMessage(std::string &message) const;
    bool isValidCommand(char c) const;

    const std::string getIpFromClientData(ClientData *clientData) const;

    void logClientData(ClientData* clientData) const;
    void logHasStrCRLF(const std::string &str);





private:  // server network data
    SOCKET_FD mServerListenSocket;
    sockaddr_in mServerAddress;
    socklen_t mServerAddressLength;

    KQUEUE_FD mhKqueue;

private: // server configuration
    int mPort;
    std::string mServerPassword;


private: // server data

    std::map<SOCKET_FD, ClientData*>    mFdToClientGlobalMap;
    std::map<std::string, ClientData*>  mNickToClientGlobalMap;
    std::map<std::string, Channel*>     mNameToChannelGlobalMap;

    std::queue<SOCKET_FD> mClientRecvProcessQueue;

    time_t mServerStartTime;
    time_t mServerLastPingTime; //< to kick if not received in 2 seconds

};