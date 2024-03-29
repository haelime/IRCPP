#pragma once

#include <string>
#include <vector> // to send message to all clients
#include <queue> // to store messages to send
#include <map> // to store connected clients

#include "macro.hpp"
#include "Server.hpp"
#include "ClientData.hpp"

typedef int SOCKET_FD;

class Server;
class ClientData;

// This class only created when a client calls JOIN command, and deleted when the last client leaves the channel
// So we choose to use a map in the server class, with the key being the channel name, and the value being the Channel object
class Channel
{
public: // constructor, destructor

    // when there is same channel name, the server will find the Channel object and add the client to the vector
    Channel(std::string newChannelName) : mChannelName(newChannelName){};
    // Channel(std::string newChannelName, std::string newChannelPassword) : mChannelName(newChannelName), mChannelPassword(newChannelPassword) {};

    // when there is no same channel name, the server will create this class and set the operatorClient as the first client and operator
    // Channel(ClientData *operatorClient, std::string newChannelName) : mChannelName(newChannelName)
    // {
        // setOperatorClient(operatorClient);
    // };
    // Channel(ClientData *operatorClient, std::string newChannelName, std::string newChannelPassword) : mChannelName(newChannelName), mChannelPassword(newChannelPassword) {};

    virtual ~Channel() {};

public: // getter, setters

    // when 
    void setOperatorClient(ClientData *operatorClient) { mOperatorClient = operatorClient; };
    void setTopic(std::string &topic) { mTopic = topic; };
    void setMode(std::string &mode) { mMode = mode; };
    void setChannelPassword(std::string &password) { mChannelPassword = password; };
    
    const std::string &getTopic() const { return mTopic; };
    const std::string &getMode() const { return mMode; };
    const std::string& getChannelName() const { return mChannelName; };

    
    // void addClient(ClientData *clientData) { mNameToClientDataMap[clientData->getClientSocket()] = clientData; };
    // void removeClient(ClientData *clientData) { mNameToClientDataMap.erase(clientData->getClientSocket()); };

    const std::map<std::string, ClientData *> &getClients() { return mNickToClientDataMap; };



private:
    // prevent copy
    // Channel() {};
    Channel(const Channel& rhs) { (void)rhs; };
    Channel &operator=(const Channel &rhs) { (void) rhs; return *this; };

private: // data
    // operator client is the first client who created the channel
    ClientData *mOperatorClient;
    std::string mTopic;
    std::string mMode;

    // when a client joins a channel, the server will create this class and add the client to the vector
    std::map<std::string, ClientData *> mNickToClientDataMap;

    std::string mChannelName;
    std::string mChannelPassword;
};