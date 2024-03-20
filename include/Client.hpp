#pragma once

#include <arpa/inet.h>
#include <time.h>
#include <string>
#include <map>
#include "Channel.hpp"

// Client Must have it's information to be able to send and receive messages
class Client
{
public: // constructor, destructor
    Client(sockaddr_in newClientAddress) {};
    virtual ~Client() {};






private:
    // prevent copy
    Client() {};
    Client(const Client& rhs) { (void)rhs; };
    Client& operator=(const Client& rhs) { (void)rhs; return *this; };


public: // getter, setters
    void setClientNickname(std::string& nickname) { mClientNickname = nickname; };
    const std::string& getClientNickname() const { return mClientNickname; };

    void setLastMessageTime(time_t& time) { lastMessageTime = time; };
    const time_t& getLastMessageTime() const { return lastMessageTime; };

    void setLastPingTime(time_t& time) { lastPingTime = time; };
    const time_t& getLastPingTime() const { return lastPingTime; };

    void addConnectedChannel(Channel* channel) { mConnectedChannels[channel->getChannelName()] = channel; };
    void removeConnectedChannel(Channel* channel)
    {
        if (mConnectedChannels.find(channel->getChannelName() != mConnectedChannels.end()))
        {
            delete mConnectedChannels[channel->getChannelName()];
        }
        mConnectedChannels.erase(channel->getChannelName());
    };
    const std::map <std::string, Channel*>& getConnectedChannels() { return mConnectedChannels; };

private:
    // Client's nickname, empty if not set
    std::string mClientNickname;

    // Client's Real Name(Address), Can be empty, must be unique
    sockaddr_in mClientAddress;
    // Client's status
    // bool status;
    // Client's last message time to limit 2 seconds
    time_t lastMessageTime;
    // Client's last ping time to kick if not received in 2 seconds
    time_t lastPingTime;

    std::map <std::string, Channel*> mConnectedChannels;

private:
    std::string mReceivedMessage;
};