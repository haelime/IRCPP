#include "Server.hpp"
#include "Channel.hpp"

bool Server::parseRecvMsgToClientData(std::pair<SOCKET_FD, std::string>& recvMsg)
{
    std::map<SOCKET_FD, ClientData*>::const_iterator clientDataIter = mFdToClientGlobalMap.find(recvMsg.first);
    if (clientDataIter == mFdToClientGlobalMap.end())
    {
        Logger::log(ERROR, "ClientData not found\n");
        return false;
    }
    ClientData* clientData = (*clientDataIter).second;

    std::string dataString = recvMsg.second;
    clientData->appendData(dataString);

    // TODO : try Parse, if fails, return false and leave clientData
    // Inputs are like these
    // PASS 1234
    // NICK client
    // USER client 0 * :realname
    // JOIN #test
    // PRIVMSG #test :Hello, server!
    // QUIT

    // Enjoy!


    return true;
}
