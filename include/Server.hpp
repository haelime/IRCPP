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
#include "MessageHandler.hpp"
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
    bool checkAndSetArgv(int argc, char** argv); 
    void init_server(void);
    void run();
    void stop(){};


private:
    MessageHandler mMessageHandler;

    // server network data
private:
    SOCKET_FD mServerListenSocket;
    sockaddr_in mServerAddress;
    socklen_t mServerAddressLength;

    KQUEUE_FD mhKq;
    struct kevent mEvent;

    // key is socket, value is ClientData, which contains all the information about the client
    // when a new client connects, a new ClientData object is created and added
    // when a client disconnects, the ClientData object is deleted


// arguments
private:
    int mPort;
    std::string mServerPassword;

     // server data
private:
    // ClientData has is's channel information, so we don't need to store channel information in server
    std::map<SOCKET_FD, ClientData*> mClientDataMap;
    std::map<std::string, Channel*> mChannelMap;

    std::queue<std::pair<SOCKET_FD, std::string> > mServerDataQueue;
    std::vector<struct kevent> mEventVector;

    time_t mServerStartTime;
    time_t mServerLastPingTime; // to kick if not received in 2 seconds

};