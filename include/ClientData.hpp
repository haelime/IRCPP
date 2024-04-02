#pragma once

#include <arpa/inet.h>
#include <time.h>
#include <string>
#include <map>
#include "Channel.hpp"
#include "types.hpp"
#include "defines.hpp"

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
    void setIsRegistered(bool isRegistered) { mIsRegistered = isRegistered; };
    const bool& getIsRegistered() const { return mIsRegistered; };

    const sockaddr_in& getClientAddress() const { return mClientAddress; };

    const std::string& getClientNickname() const { return mClientNickname; };
    void setClientNickname(std::string& nickname) { mClientNickname = nickname; };

    const time_t& getLastMessageTime() const { return lastMessageTime; };
    void setLastMessageTime(time_t& time) { lastMessageTime = time; };

    const time_t& getLastPingTime() const { return lastPingTime; };
    void setLastPingTime(time_t time) { lastPingTime = time; };

    std::string& getReceivedString(void) { return mReceivedString; };
    void setReceivedString(const std::string& recvStr) { mReceivedString = recvStr; };

    const std::string& getUsername() const { return mUsername; };
    void setUsername(std::string& username) { mUsername = username; };

    const std::string& getHostname() const { return mHostname; };
    void setHostname(std::string& hostname) { mHostname = hostname; };

    const std::string& getServername() const { return mServername; };
    void setServername(std::string& servername) { mServername = servername; };

    const std::string& getRealname() const { return mRealname; };
    void setRealname(std::string& realname) { mRealname = realname; };

    const SOCKET_FD& getClientSocket() const { return mClientSocket; };
    void setClientSocket(SOCKET_FD& clientSocket) { mClientSocket = clientSocket; };

    void    setIp(std::string& ip) { mClientIp = ip; };
    const std::string& getIp() const { return mClientIp; };

    std::queue <Message>& getServerToClientSendQueue() { return mServerToClientSendQueue; };
    std::map <std::string, Channel*>& getConnectedChannels() { return mNameToConnectedChannelMap; };
    std::queue <Message> &getExecuteMessageQueue() { return mParsedMessageQueue; };

public:
    // should handle error if the recvStr is too big
    void appendReceivedString(const std::string& recvStr) { mReceivedString.append(recvStr); };
    void clearReceivedString() { mReceivedString.clear(); };

    // void addConnectedChannel(Channel* channel);
    // void removeConnectedChannel(Channel* channel);

private:
    // Client's nickname, empty if not set
    std::string mClientNickname;

    // Client's Real Name(Address), Cannot be empty, must be unique
    sockaddr_in mClientAddress;
    std::string mClientIp;

    SOCKET_FD mClientSocket;
    // User information
    std::string mUsername;
    std::string mHostname;
    std::string mServername;
    std::string mRealname;

    // Client's last message time to limit 2 seconds
    time_t lastMessageTime;
    // Client's last ping time to kick if not received in 2 seconds
    time_t lastPingTime;

    // get raw recv string, parse, push to queue
    std::map <std::string, Channel*>    mNameToConnectedChannelMap;
    std::queue <Message>                mParsedMessageQueue;

    // send queue, first vector is the command, least are the params
    std::queue <Message>  mServerToClientSendQueue;

    bool mIsRegistered;

private:
    std::string mReceivedString;

};