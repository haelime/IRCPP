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
    void stop(){};


private:
    void assembleDataToMessage(std::pair<SOCKET_FD, std::string>& data)
    {
        std::map<SOCKET_FD, ClientData*>::const_iterator clientDataIter = mFdToClientDataMap.find(data.first);
        if (clientDataIter == mFdToClientDataMap.end())
        {
            Logger::log(ERROR, "ClientData not found\n");
            return;
        }
        ClientData* clientData = (*clientDataIter).second; // cuz it's map, it's O(logN)

        std::string dataString = data.second;
        clientData->appendData(dataString);
        if (isValidMessage(clientData->getReceivedData()))
        {
            Message message;

            // TODO : parse the message
            (void)message;
        }
        return;
    }

    bool isValidMessage(std::string& data)
    {
        // if the data is too small, we can't make a message
        if (data.size() < 2)
        {
            return false;
        }

        // if the data is too big, we should handle error
        if (data.size() > MAX_MESSAGE_LENGTH)
        {
            return false;
        }

        // if the data is not ended with \r\n, we can't make a message
        if (data[data.size() - 2] != '\r' || data[data.size() - 1] != '\n')
        {
            return false;
        }

        // if the data is ended with \r\n, we can make a message
        return true;
    };

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
    std::map<SOCKET_FD, ClientData*> mFdToClientDataMap;
    std::map<std::string, Channel*> mChannelMap;

    std::queue<std::pair<SOCKET_FD, std::string> > mServerDataQueue;
    std::vector<struct kevent> mEventVector;

    time_t mServerStartTime;
    time_t mServerLastPingTime; // to kick if not received in 2 seconds

};