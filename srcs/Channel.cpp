#include "Channel.hpp"

const Message Channel::getNameReply(const ClientData *requestClient)
{
    Message reply;
    reply.mCommand = NONE;
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
    names.pop_back();
    reply.mMessageTokens.push_back(names);
    return reply;
}

const Message Channel::getEndOfNames(const ClientData *requestClient)
{
    Message reply;
    reply.mCommand = NONE;
    reply.mMessageTokens.push_back(RPL_ENDOFNAMES);
    reply.mMessageTokens.push_back(requestClient->getClientNickname());
    reply.mMessageTokens.push_back(mChannelName);
    reply.mMessageTokens.push_back("End of /NAMES list.");
    return reply;
}