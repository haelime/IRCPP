#pragma once

#include <string>
#include <vector> // to send message to all clients
#include <queue> // to store messages to send
#include <map> // to store connected clients

#include "defines.hpp"
#include "types.hpp"
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
    // Channel(std::string newChannelName, std::string newChannelPassword) : mChannelName(newChannelName), mPassword(newChannelPassword) {};

    // when there is no same channel name, the server will create this class and set the operatorClient as the first client and operator
    // Channel(ClientData *operatorClient, std::string newChannelName) : mChannelName(newChannelName)
    // {
        // setOperatorClient(operatorClient);
    // };
    // Channel(ClientData *operatorClient, std::string newChannelName, std::string newChannelPassword) : mChannelName(newChannelName), mPassword(newChannelPassword) {};

    virtual ~Channel() {};

public: // getter, setters

    void clearPassword() { mPassword.clear(); };
    void setTopic(std::string &topic) { mTopic = topic; };
    void setMode(std::string &mode) { mMode = mode; };
    void setPassword(std::string &password) { mPassword = password; };
    void setInviteOnly(bool isInviteOnly) { mIsInviteOnly = isInviteOnly; };
    void setTopicRestricted(bool isTopicRestricted) { mIsTopicRestricted = isTopicRestricted; };
    void setKeyProtected(bool isKeyProtected) { mIsKeyProtected = isKeyProtected; };
    void setUserLimit(int userLimit) { mUserLimit = userLimit; };
    
    const std::string &getTopic() const { return mTopic; };
    const std::string &getMode() const { return mMode; };
    const std::string& getName() const { return mChannelName; };
    const std::string& getPassword() const { return mPassword; };
    const bool& getIsInviteOnly() const { return mIsInviteOnly; };
    const bool& getIsTopicRestricted() const { return mIsTopicRestricted; };
    const bool& getIsKeyProtected() const { return mIsKeyProtected; };
    const int& getUserLimit() const { return mUserLimit; };

    // 353 RPL_NAMREPLY
    const Message getNameReply(sockaddr_in* serverAddr, const ClientData* requestClient);

    // 366 RPL_ENDOFNAMES
    const Message getEndOfNames(sockaddr_in* serverAddr, const ClientData *requestClient);

    std::map<std::string, ClientData *> &getNickToClientDataMap() { return mNickToClientDataMap; };
    std::map<std::string, ClientData *> &getNickToOperatorClientsMap() { return mNickToOperatorClientsMap; };

private:
    // prevent copy
    // Channel() {};
    Channel(const Channel& rhs) { (void)rhs; };
    Channel &operator=(const Channel &rhs) { (void) rhs; return *this; };

private: // data
    // operator client is the first client who created the channel
    std::string mTopic;
    std::string mMode;

    bool        mIsInviteOnly;
    bool        mIsTopicRestricted;
    bool        mIsKeyProtected;
    int         mUserLimit;

    // when a client joins a channel, the server will create this class and add the client to the vector
    std::map<std::string, ClientData *> mNickToClientDataMap;
    std::map<std::string, ClientData *> mNickToOperatorClientsMap;

    std::string mChannelName;
    std::string mPassword;
};