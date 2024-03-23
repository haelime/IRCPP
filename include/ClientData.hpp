#pragma once

#include <arpa/inet.h>
#include <time.h>
#include <string>
#include <map>
#include "Channel.hpp"

class Channel;

// ClientData Must have it's information, and it's connected channels
class ClientData
{

public: // constructor, destructor
    ClientData(sockaddr_in newClientAddress) :mClientAddress(newClientAddress) {};
    virtual ~ClientData() {};

private:
    // prevent copy
    ClientData() {};
    ClientData(const ClientData& rhs) { (void)rhs; };
    ClientData& operator=(const ClientData& rhs) { (void)rhs; return *this; };


public: // getter, setters
    const sockaddr_in& getClientAddress() const { return mClientAddress; };

    void setClientNickname(std::string& nickname) { mClientNickname = nickname; };
    const std::string& getClientNickname() const { return mClientNickname; };

    void setLastMessageTime(time_t& time) { lastMessageTime = time; };
    const time_t& getLastMessageTime() const { return lastMessageTime; };

    void setLastPingTime(time_t& time) { lastPingTime = time; };
    const time_t& getLastPingTime() const { return lastPingTime; };

    std::string& getReceivedData(void) { return mReceivedData; };

    const std::map <std::string, Channel*>& getConnectedChannels() { return mNameToConnectedChannelMap; };

public:
    // should handle error if the data is too big
    void appendData(const std::string& data)
    {
        mReceivedData.append(data);
    };

    void clearData()
    {
        mReceivedData.clear();
    };

    


private:
    // Client's nickname, empty if not set
    std::string mClientNickname;

    // Client's Real Name(Address), Cannot be empty, must be unique
    sockaddr_in mClientAddress;

    // Client's last message time to limit 2 seconds
    time_t lastMessageTime;
    // Client's last ping time to kick if not received in 2 seconds
    time_t lastPingTime;

    std::map <std::string, Channel*>    mNameToConnectedChannelMap;

private:
    std::string mReceivedData;

};