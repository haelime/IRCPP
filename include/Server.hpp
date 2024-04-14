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
    Server() : mIsRunning(false) {};
    ~Server() {};

    void printUsage(char** argv)
    {
        std::cerr << "Usage : " << argv[0] << " <port> <password>\n";
    }
    bool initServer(int argc, char** argv);
    void run();
    void stop() {}; // TODO : implement

    std::map<SOCKET_FD, ClientData*>& getFdToClientGlobalMap() { return mFdToClientGlobalMap; }
    std::map<std::string, Channel*>& getNameToChannelGlobalMap() { return mNameToChannelGlobalMap; }


private:
    bool setPortAndPassFromArgv(int argc, char** argv);

    // Try parse RecvMsg
    // ClientData Does NOTHING about this recvMsg, only server will handle it.
    bool parseReceivedRequestFromClientData(ClientData *client);

    void executeParsedMessages(ClientData* clientData);
    bool isValidMessage(const Message& message) const;
    bool isValidCommand(char c) const;
    bool isValidParameter(char c) const;

    const std::string getIpFromClientData(ClientData *clientData) const;

    void logClientData(ClientData* clientData) const;
    void logHasStrCRLF(const std::string &str);

    void connectClientDataWithChannel(ClientData *clientData, Channel *channel);
    void connectClientDataWithChannel(ClientData *clientData, Channel *channel, const std::string &password);

    void disconnectClientDataWithChannel(ClientData *clientData, Channel *channel);
    void disconnectClientDataFromServer(ClientData *clientData);

    void logMessage(const Message &message) const;

    void sendChannelJoinSucessMessageToClientData(ClientData *clientData, Channel *channel);
    void sendMessagetoChannel(Channel* channel, const Message& message);

    void sendWelcomeMessageToClientData(ClientData *clientData);

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

    std::queue<SOCKET_FD> mRecvedStrPerClientDataProcessQueue;

    time_t mServerStartTime;
    time_t mServerLastPingTime; //< to kick if not received in 2 seconds
    bool mIsRunning;

};