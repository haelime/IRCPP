#include "ClientData.hpp"

const SOCKET_FD& ClientData::getClientSocket() const { return mClientSocket; };
void ClientData::setClientSocket(SOCKET_FD& clientSocket) { mClientSocket = clientSocket; };