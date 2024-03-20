#pragma once

#include <string>
#include <vector> // to send message to all clients
#include <queue> // to store messages to send
#include "Server.hpp"
#include "Client.hpp"

// This class only created when a client calls JOIN command, and deleted when the last client leaves the channel
// So we choose to use a map in the server class, with the key being the channel name, and the value being the Channel object
class Channel
{
public: // constructor, destructor

    // when there is same channel name, the server will find the Channel object and add the client to the vector
    Channel(std::string newChannelName) : mChannelName(newChannelName) {};
    Channel(std::string newChannelName, std::string newChannelPassword) : mChannelName(newChannelName), mChannelPassword(newChannelPassword) {};

    // when there is no same channel name, the server will create this class and set the operatorClient as the first client and operator
    Channel(Client *operatorClient, std::string newChannelName) : mChannelName(newChannelName) {};
    Channel(Client *operatorClient, std::string newChannelName, std::string newChannelPassword) : mChannelName(newChannelName), mChannelPassword(newChannelPassword) {};

    virtual ~Channel() {};

public: // getter, setters

    // when 
    void setTopic(std::string &topic) const { mTopic = topic; };
    const std::string &getTopic() { return mTopic; };

    void setMode(std::string &mode) const { mMode = mode; };
    const std::string &getMode() { return mMode; };


private:
    // prevent copy
    Channel() {};
    Channel(const Channel &rhs) { (void) rhs; };
    Channel &operator=(const Channel &rhs) { (void) rhs; return *this; };

    
    Server &mServer;

    // when a client joins a channel, the server will create this class and add the client to the vector
    std::map<Client *> mClients;
    std::string mChannelName;
}