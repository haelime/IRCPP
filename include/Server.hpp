#pragma once

#include <arpa/inet.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <unistd.h>

#include <iostream>
#include <string>
#include <vector>
#include <utility>

#include "macro.hpp"
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

struct Message
{
    std::string mReceivingChannelName;
    std::string mMessage;
    std::string mSender;
    std::string mReceiver;
};

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
    void stop(){}; // TODO : implement


private:
    bool setPortAndPassFromArgv(int argc, char** argv); 

    // Try parse RecvMsg
    // ClientData Does NOTHING about this recvMsg, only server will handle it.
    bool parseRecvMsgToClientData(std::pair<SOCKET_FD, std::string>& recvMsg);
    // Please, Add your methods below this line :)



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
    std::map<std::string, Channel*>     mNameToChannelGlobalMap;

    std::queue<std::pair<SOCKET_FD, std::string> > mClientRecvMsgQueue;

    time_t mServerStartTime;
    time_t mServerLastPingTime; //< to kick if not received in 2 seconds

};