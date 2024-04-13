#pragma once

#include <arpa/inet.h>
#include <time.h>
#include <string>
#include <map>
#include "Channel.hpp"
#include "types.hpp"
#include "defines.hpp"

class Channel;
typedef int SOCKET_FD;

// ClientData Must have it's information, and it's connected channels
class ClientData
{

public: // constructor, destructor
    ClientData(sockaddr_in newClientAddress) :mClientAddress(newClientAddress), mIsPassed(false), mIsNickSet(false) ,mIsUserSet(false), mIsReadyToChat(false) {};
    virtual ~ClientData() {};

private:
    // prevent copy
    ClientData() {};
    ClientData(const ClientData& rhs) { (void)rhs; };
    ClientData& operator=(const ClientData& rhs) { (void)rhs; return *this; };


public: // getter, setters
    void setIsReadyToChat(bool isReadyToChat) { mIsReadyToChat = isReadyToChat; };
    const bool& getIsReadyToChat() const { return mIsReadyToChat; };

    void setIsPassed(bool isRegistered) { mIsPassed = isRegistered; };
    const bool& getIsPassed() const { return mIsPassed; };

    void setIsNickSet(bool isNickSet) { mIsNickSet = isNickSet; };
    const bool& getIsNickSet() const { return mIsNickSet; };

    void setIsUserSet(bool isUserSet) { mIsUserSet = isUserSet; };
    const bool& getIsUserSet() const { return mIsUserSet; };

    const sockaddr_in& getClientAddress() const { return mClientAddress; };

    const std::string& getClientNickname() const { return mClientNickname; };
    void setClientNickname(std::string& nickname) { mClientNickname = nickname; };

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

    const SOCKET_FD& getClientSocket() const;
    void setClientSocket(SOCKET_FD& clientSocket);

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

    // get raw recv string, parse, push to queue
    std::map <std::string, Channel*>    mNameToConnectedChannelMap;
    std::queue <Message>                mParsedMessageQueue;

    // send queue, first vector is the command, least are the params
    std::queue <Message>  mServerToClientSendQueue;

    bool mIsPassed;
    bool mIsNickSet;
    bool mIsUserSet;
    bool mIsReadyToChat;

private:
    std::string mReceivedString;

};