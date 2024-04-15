#include "Channel.hpp"

// 353
const Message Channel::getNameReply(sockaddr_in *serverAddr , const ClientData *requestClient)
{
    Message reply;
    reply.mCommand = NONE;
    reply.mHasPrefix = true;
    reply.mMessageTokens.push_back(":" + std::string(inet_ntoa(serverAddr->sin_addr)));
    reply.mMessageTokens.push_back(RPL_NAMREPLY);
    reply.mMessageTokens.push_back(requestClient->getClientNickname());
    reply.mMessageTokens.push_back("=");
    reply.mMessageTokens.push_back(mChannelName);
    std::string names;
    names += ":";
    for (std::map<std::string, ClientData*>::const_iterator it = mNickToClientDataMap.begin(); it != mNickToClientDataMap.end(); it++)
    {
        std::map<std::string, ClientData*>::const_iterator opit = mNickToOperatorClientsMap.find(it->first);
        if (opit != mNickToOperatorClientsMap.end())
            names += "@";
        names += it->first + " ";
    }
    names.erase(names.length()-1, 1);
    reply.mMessageTokens.push_back(names);
    return reply;
}

// 366
const Message Channel::getEndOfNames(sockaddr_in *serverAddr ,const ClientData *requestClient)
{
    Message reply;
    reply.mCommand = NONE;
    reply.mHasPrefix = true;
    reply.mMessageTokens.push_back(":" + std::string(inet_ntoa(serverAddr->sin_addr)));
    reply.mMessageTokens.push_back(RPL_ENDOFNAMES);
    reply.mMessageTokens.push_back(requestClient->getClientNickname());
    reply.mMessageTokens.push_back(mChannelName);
    reply.mMessageTokens.push_back(":End of /NAMES list.");
    return reply;
}