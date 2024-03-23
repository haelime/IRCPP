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
    bool checkAndSetArgv(int argc, char** argv); 
    void init_server(void);
    void run();
    void stop(){}; // TODO : implement


private:
    void assembleDataToMessage(std::pair<SOCKET_FD, std::string>& data);

    bool isValidMessage(std::string& data);

    // void connectClientToChannel(const std::string &channelName);
    // void disconnectClientFromChannel(const std::string &channelName);
    // void disconnectClientFromChannel(const std::string &channelName, const std::string &reason);



    // server network data
private:
    SOCKET_FD mServerListenSocket;
    sockaddr_in mServerAddress;
    socklen_t mServerAddressLength;

    KQUEUE_FD mhKq;
    // kernal monitor events
    struct kevent mEvent;
    // client events
    std::vector<struct kevent> mEventVector;

private: // arguments
    int mPort;
    std::string mServerPassword;

     
private: // server data
    // ClientData has is's channel information, so we don't need to store channel information in server

    std::map<SOCKET_FD, ClientData*>    mFdToEveryClientDataMap;
    std::map<std::string, Channel*>     mNameToEveryChannelMap;

    std::queue<std::pair<SOCKET_FD, std::string> > mServerDataQueue;


    time_t mServerStartTime;
    time_t mServerLastPingTime; // to kick if not received in 2 seconds

};