#include <fcntl.h>
#include "Server.hpp"
#include "ClientData.hpp"
#include "Channel.hpp"
#include "Logger.hpp"

// TODO : NEED TO FIX EVERY std::to_string()

void Server::init_server(void)
{
    // make socket FD
    mServerListenSocket = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    Logger::log(DEBUG, "Server is creating socket...");
    if (SOCKET_ERROR == mServerListenSocket)
    {
        Logger::log(FATAL, "Failed to create socket");
        std::perror("socket");
        assert(0);
        exit(1);
    }
    Logger::log(DEBUG, "Server created socket");

    // set Server's address
    mServerAddress.sin_addr.s_addr = INADDR_ANY;
    mServerAddress.sin_port = htons(mPort);
    mServerAddress.sin_family = AF_INET;
    mServerAddress.sin_len = sizeof(mServerAddress);
    mServerAddressLength = mServerAddress.sin_len;

    // bind server's address & port
    Logger::log(DEBUG, "Server is binding socket...");
    if (SOCKET_ERROR == bind(mServerListenSocket, (const sockaddr*)&mServerAddress,
        mServerAddressLength))
    {
        Logger::log(FATAL, "Failed to bind socket");
        std::perror("bind");
        close(mServerListenSocket);
        assert(0);
        exit(1);
    }
    Logger::log(DEBUG, "Server binded socket");

    // start listening on port
    Logger::log(DEBUG, "Server is listening on socket...");
    if (SOCKET_ERROR == listen(mServerListenSocket, SOMAXCONN))
    {
        Logger::log(FATAL, "Failed to listen on socket");
        std::perror("listen");
        close(mServerListenSocket);
        assert(0);
        exit(1);
    }

    // init kq
    Logger::log(DEBUG, "Server is creating kqueue...");
    mhKq = kqueue();
    if (SOCKET_ERROR == mhKq)
    {
        Logger::log(FATAL, "Failed to create kqueue");
        std::perror("kqueue");
        close(mServerListenSocket);
        assert(0);
        exit(1);
    }
    Logger::log(DEBUG, "Server created kqueue");

    // add event filter
    mEvent.ident = mServerListenSocket; // trace this socket
    mEvent.filter = EVFILT_READ; // when read event occurs
    mEvent.flags = EV_ADD; // add event, if it's already added, it will be ignored
    mEvent.data = 0; // it means Filter-specific data value
    mEvent.udata = NULL; // no user data


    // is it nessasary? IDK but it's fast enough
    mEventVector.resize(256);

    Logger::log(DEBUG, "Server is initiating...");


    // kevent returns number of events placed in the eventlist
    if (KQUEUE_ERROR == kevent(mhKq, &mEvent, 1, NULL, 0, NULL))
    {
        Logger::log(FATAL, "Failed to add event to kqueue");
        std::perror("kevent");
        close(mServerListenSocket);
        assert(0);
        exit(1);
    }

    std::stringstream ss;

    Logger::log(INFO, "Sucessfully initiated server");
    Logger::log(INFO, "Server is listening on port " + std::to_string(mPort) + " with password " + mServerPassword);
    Logger::log(DEBUG, "Port : " + std::to_string(mPort));
    Logger::log(DEBUG, "Password : " + mServerPassword);
}

void Server::run()
{
    // to wait for event infinitely or just for 0 seconds
    // timespec timespecInf;
    // timespecInf.tv_nsec = 0;
    // timespecInf.tv_sec = 0;

    // [2021-01-01 12:00:00]
    mServerStartTime = time(NULL);

    Logger::log(INFO, "Server is running...");
    mServerLastPingTime = time(NULL);

    // main loop for server
    // it will run until server is stopped and check event for every 1 second
    timespec serverTick;
    serverTick.tv_nsec = 0; // 1000000 * 50 == 50 milliseconds
    serverTick.tv_sec = 0;
    while (true)
    {
        // kevent returns number of events placed in the eventlist
        // Logger::log(DEBUG, "Server is waiting for event...");
        size_t eventCount = kevent(mhKq, NULL, 0, mEventVector.data(), mEventVector.size(), &serverTick);

        if (KQUEUE_ERROR == (int)eventCount)
        {
            Logger::log(FATAL, "Failed to get event from kqueue");
            std::perror("kevent");
            close(mServerListenSocket);
            assert(0);
            exit(1);
        }
        // Logger::log(DEBUG, "Server got " + std::to_string(eventCount) + " events");

        // When eventCount is almost same as mEventVector.size(), it means we need to resize mEventVector
        // [@@@@@@@@@@ 50 ]
        // WHY 50? I don't know, need to test
        const int EVENTBUFFER_RESIZE_LIMIT = 50;
        if (eventCount + EVENTBUFFER_RESIZE_LIMIT > mEventVector.size())
        {
            Logger::log(WARNING, "Event vector is too small, resizing...");
            mEventVector.resize(mEventVector.size() * 2);
            // calculate memory size to killo, megabyte, gigabyte
            // 1. sizeof(struct kevent) * mEventVector.size()
            size_t size = sizeof(struct kevent) * mEventVector.size();
            if (size < 1024)
                Logger::log(WARNING, "Event vector resized, Current size : " + std::to_string(size) + " bytes");
            else if (size < 1024 * 1024)
                Logger::log(WARNING, "Event vector resized, Current size : " + std::to_string(size / 1024) + " kilobytes");
            else if (size < 1024 * 1024 * 1024)
                Logger::log(WARNING, "Event vector resized, Current size : " + std::to_string(size / 1024 / 1024) + " megabytes");
            else
                Logger::log(WARNING, "Event vector resized, Current size : " + std::to_string(size / 1024 / 1024 / 1024) + " gigabytes");
        }

        // handle events
        for (size_t i = 0; i < eventCount; i++)
        {
            if (mEventVector[i].flags & EV_ERROR)
            {
                Logger::log(ERROR, "Error occured in kqueue");
                std::perror("kevent");
                close(mServerListenSocket);
                assert(0);
                exit(1);
            }
            else if (mEventVector[i].flags & EV_EOF)
            {
                Logger::log(DEBUG, "EOF occured in kqueue, closing client socket and deleting clientData object");
                std::perror("kevent");

                // find the clientData
                Logger::log(DEBUG, "Finding clientData object");
                ClientData* clientData = mFdToEveryClientDataMap[mEventVector[i].ident]; // cuz it's map, it's O(logN)
                delete clientData;
                mFdToEveryClientDataMap.erase(mEventVector[i].ident);
                close(mEventVector[i].ident);
                // assert(0);
            }
            else if (mEventVector[i].flags & EVFILT_READ)
            {
                // new client is trying to connect
                if (static_cast<int>(mEventVector[i].ident) == mServerListenSocket)
                {
                    sockaddr_in newClientAddress;
                    socklen_t newClientAddressLength = sizeof(newClientAddress);
                    SOCKET_FD newClientSocket = accept(mServerListenSocket, (sockaddr*)&newClientAddress, &newClientAddressLength);
                    Logger::log(DEBUG, "New client is trying to connect");
                    if (SOCKET_ERROR == newClientSocket)
                    {
                        Logger::log(FATAL, "Failed to accept new client");
                        std::perror("accept");
                        close(mServerListenSocket);
                        assert(0);
                        exit(1);
                    }

                    Logger::log(INFO, "New client connected");

                    Logger::log(DEBUG, "-----------------------------------------");
                    Logger::log(DEBUG, "SocketDescriptor : " + std::to_string(newClientSocket));
                    Logger::log(DEBUG, "IP : " + std::string(inet_ntoa(newClientAddress.sin_addr)));
                    Logger::log(DEBUG, "Client's Port : " + std::to_string(ntohs(newClientAddress.sin_port)));
                    Logger::log(DEBUG, "-----------------------------------------");

                    Logger::log(DEBUG, "Setting non-blocking socket");
                    if (fcntl(newClientSocket, F_SETFL, O_NONBLOCK) == -1)
                    {
                        Logger::log(FATAL, "Failed to set non-blocking socket");
                        std::perror("fcntl");
                        close(mServerListenSocket);
                        close(newClientSocket);
                        assert(0);
                        exit(1);
                    }
                    Logger::log(DEBUG, "Socket set to non-blocking");

                    // add new clientData to kqueue
                    struct kevent newClientEvent;
                    memset(&newClientEvent, 0, sizeof(newClientEvent));
                    newClientEvent.ident = newClientSocket;
                    newClientEvent.filter = EVFILT_READ;
                    newClientEvent.flags = EV_ADD;
                    newClientEvent.data = 0;
                    newClientEvent.udata = NULL;

                    Logger::log(DEBUG, "Adding new client to kqueue");
                    if (KQUEUE_ERROR == kevent(mhKq, &newClientEvent, 1, NULL, 0, NULL))
                    {
                        Logger::log(FATAL, "Failed to add new client to kqueue");
                        std::perror("kevent newClientEvent");
                        close(mServerListenSocket);
                        close(newClientSocket);
                        assert(0);
                        exit(1);
                    }
                    Logger::log(DEBUG, "New client added to kqueue");

                    // create new clientData object
                    Logger::log(DEBUG, "Creating new clientData object");
                    ClientData* newClientData = new ClientData(newClientAddress);
                    Logger::log(DEBUG, "New clientData object created");

                    std::string ip = inet_ntoa(newClientAddress.sin_addr);
                    Logger::log(DEBUG, "New clientData object address : " + ip);


                    // it's same as mFdToEveryClientDataMap.insert(std::pair<SOCKET_FD, ClientData*>(newClientSocket, newClientData));
                    Logger::log(DEBUG, "Adding new clientData object to map");
                    mFdToEveryClientDataMap[newClientSocket] = newClientData;
                    Logger::log(DEBUG, "New clientData object added to map");
                }

                // if it's not server socket, it means client is trying to send message
                else
                {
                    Logger::log(DEBUG, "Client is trying to send message");
                    // find the clientData
                    Logger::log(DEBUG, "Finding clientData object");
                    ClientData* clientData = mFdToEveryClientDataMap[mEventVector[i].ident]; // cuz it's map, it's O(logN)
                    if (clientData == NULL)
                    {
                        Logger::log(ERROR, "ClientData not found, closing socket");
                        close(mEventVector[i].ident);
                        assert(0);
                        continue;
                    }
                    Logger::log(DEBUG, "ClientData object found");

                    // get message from client
                    Logger::log(DEBUG, "Receiving data from client");
                    char data[MAX_MESSAGE_LENGTH];
                    int dataLength = recv(mEventVector[i].ident, data, MAX_MESSAGE_LENGTH, 0);
                    if (SOCKET_ERROR == dataLength)
                    {
                        Logger::log(ERROR, "Failed to receive data from client");
                        std::perror("recv");
                        close(mEventVector[i].ident);
                        assert(0);
                        continue;
                    }

                    Logger::log(INFO, clientData->getClientNickname() + " sent message : " + std::string(data, dataLength));

                    Logger::log(DEBUG, "-----------------------------------------");
                    Logger::log(DEBUG, "Data received from client");
                    Logger::log(DEBUG, "NickName : " + clientData->getClientNickname());
                    Logger::log(DEBUG, "IP : " + std::string(inet_ntoa(clientData->getClientAddress().sin_addr)));
                    Logger::log(DEBUG, "Client's Port : " + std::to_string(ntohs(clientData->getClientAddress().sin_port)));
                    Logger::log(DEBUG, "Received Data length : " + std::to_string(dataLength));

                    // should we handle IRC protocol's \r\n? I don't know
                    Logger::log(DEBUG, "Data : " + std::string(data, dataLength));
                    Logger::log(DEBUG, "Total Data : " + clientData->getReceivedData());
                    Logger::log(DEBUG, "-----------------------------------------");

                    // if message is empty, it means client disconnected
                    if (dataLength == 0)
                    {
                        Logger::log(INFO, "Client disconnected");

                        Logger::log(DEBUG, "-----------------------------------------");
                        Logger::log(DEBUG, "NickName : " + clientData->getClientNickname());
                        Logger::log(DEBUG, "IP : " + std::string(inet_ntoa(clientData->getClientAddress().sin_addr)));
                        Logger::log(DEBUG, "Port : " + std::to_string(ntohs(clientData->getClientAddress().sin_port)));
                        Logger::log(DEBUG, "-----------------------------------------");

                        // delete clientData object
                        delete clientData;
                        mFdToEveryClientDataMap.erase(mEventVector[i].ident);
                        close(mEventVector[i].ident);
                        Logger::log(DEBUG, "ClientData object deleted");
                        continue;
                    }

                    // handle message
                    // push message to message Queue with it's clientData information
                    Logger::log(DEBUG, "Pushing message to serverDataQueue");
                    mServerDataQueue.push(std::pair<SOCKET_FD, std::string>(mEventVector[i].ident, std::string(data, dataLength)));

                }
            }
        }
        // if we handled every event, we can push messages to MessageHandler
        {
            if (time(NULL) - mServerLastPingTime > SERVER_PING_INTERVAL)
            {
                // TODO : ping clients and kick if not received in 2 seconds
                mServerLastPingTime = time(NULL);
            }


            // TODO : push messages to clients
            // we must check message's validity, hence we need to parse it, and store it in the clientData object
            while (!mServerDataQueue.empty())
            {
                // send data to MessageHandler, and it will handle the message and request to server
                std::pair<SOCKET_FD, std::string>& data = mServerDataQueue.front();
                assembleDataToMessage(data);
                mServerDataQueue.pop();
            }
        }
    }
}

bool Server::checkAndSetArgv(int argc, char** argv)
{
    // ./ircserc 9999 asdf
    if (argc != 3)
        return false;

    // if not digit
    for (int i = 0; argv[1][i] != '\0'; i++)
    {
        if (!isdigit(argv[1][i]))
            return false;
    }

    mPort = atoi(argv[1]);
    if (mPort > MAX_PORT_NUMBER || mPort < 0)
        return false;

    mServerPassword = argv[2];
    if (mServerPassword.length() > MAX_PASSWORD_LENGTH)
        return false;


    return true;
}

void Server::assembleDataToMessage(std::pair<SOCKET_FD, std::string>& data)
{
    std::map<SOCKET_FD, ClientData*>::const_iterator clientDataIter = mFdToEveryClientDataMap.find(data.first);
    if (clientDataIter == mFdToEveryClientDataMap.end())
    {
        Logger::log(ERROR, "ClientData not found\n");
        return;
    }
    ClientData* clientData = (*clientDataIter).second; // cuz it's map, it's O(logN)

    std::string dataString = data.second;
    clientData->appendData(dataString);
    if (isValidMessage(clientData->getReceivedData()))
    {
        Message message;

        // TODO : parse the message
        (void)message;
    }
    return;
}

bool Server::isValidMessage(std::string& data)
{
    // if the data is too small, we can't make a message
    if (data.size() < 2)
    {
        return false;
    }

    // if the data is too big, we should handle error
    if (data.size() > MAX_MESSAGE_LENGTH)
    {
        return false;
    }

    // if the data is not ended with \r\n, we can't make a message
    if (data[data.size() - 2] != '\r' || data[data.size() - 1] != '\n')
    {
        return false;
    }

    // if the data is ended with \r\n, we can make a message
    return true;
};


// void Server::connectClientToChannel(const std::string &channelName)
// {


// }

// void Server::disconnectClientFromChannel(const std::string &channelName)
// {
    
// }
// void Server::disconnectClientFromChannel(const std::string &channelName, const std::string &reason)
// {

// }