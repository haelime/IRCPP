#include "ClientData.hpp"

const SOCKET_FD& ClientData::getClientSocket() const { return mClientSocket; };
void ClientData::setClientSocket(SOCKET_FD& clientSocket) { mClientSocket = clientSocket; };


std::queue <Message>& ClientData::getServerToClientSendQueue()
{
    // add kevent to listen for write events
    struct kevent evSet;
    EV_SET(&evSet, mClientSocket, EVFILT_WRITE, EV_ADD, 0, 0, NULL);
    kevent(mhKqueue, &evSet, 1, NULL, 0, NULL);

    return mServerToClientSendQueue;
}