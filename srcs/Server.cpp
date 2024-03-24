#include <fcntl.h>
#include "Server.hpp"
#include "ClientData.hpp"
#include "Channel.hpp"
#include "Logger.hpp"

// TODO : NEED TO FIX EVERY std::to_string()

bool Server::initServer(int argc, char** argv)
{
    if (setPortAndPassFromArgv(argc, argv) == false)
    {
        printUsage(argv);
        return false;
    }

    // Create listen socket
    mServerListenSocket = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    Logger::log(DEBUG, "Server is creating socket...");
    if (SOCKET_ERROR == mServerListenSocket)
    {
        Logger::log(FATAL, "Failed to create socket");
        std::perror("socket");
        assert(0);
        return false;
    }
    Logger::log(DEBUG, "Server created socket");

    // Set Server's address
    mServerAddress.sin_addr.s_addr = INADDR_ANY;
    mServerAddress.sin_port = htons(mPort);
    mServerAddress.sin_family = AF_INET;
    mServerAddress.sin_len = sizeof(mServerAddress);
    mServerAddressLength = mServerAddress.sin_len;

    // Bind listen socket
    Logger::log(DEBUG, "Server is binding socket...");
    if (SOCKET_ERROR == bind(mServerListenSocket, (const sockaddr*)&mServerAddress,
        mServerAddressLength))
    {
        Logger::log(FATAL, "Failed to bind socket");
        std::perror("bind");
        close(mServerListenSocket);
        assert(0);
        return false;
    }
    Logger::log(DEBUG, "Server binded socket");

    // Start listening
    Logger::log(DEBUG, "Server is listening on socket...");
    if (SOCKET_ERROR == listen(mServerListenSocket, SOMAXCONN))
    {
        Logger::log(FATAL, "Failed to listen on socket");
        std::perror("listen");
        close(mServerListenSocket);
        assert(0);
        return false;
    }

    // Init kqueue
    Logger::log(DEBUG, "Server is creating kqueue...");
    mhKqueue = kqueue();
    if (SOCKET_ERROR == mhKqueue)
    {
        Logger::log(FATAL, "Failed to create kqueue");
        std::perror("kqueue");
        close(mServerListenSocket);
        assert(0);
        return false;
    }
    Logger::log(DEBUG, "Server created kqueue");

    // Register listen socket to kqueue
    struct kevent evListenEvent;
    evListenEvent.ident = mServerListenSocket; // trace this socket
    evListenEvent.filter = EVFILT_READ; // when read event occurs
    evListenEvent.flags = EV_ADD; // add event, if it's already added, it will be ignored
    evListenEvent.data = 0; // it means Filter-specific data value
    evListenEvent.udata = NULL; // no user data

    Logger::log(DEBUG, "Server is initiating...");

    if (KQUEUE_ERROR == kevent(mhKqueue, &evListenEvent, 1, NULL, 0, NULL))
    {
        Logger::log(FATAL, "Failed to add event to kqueue");
        std::perror("kevent");
        close(mServerListenSocket);
        assert(0);
        return false;
    }

    Logger::log(INFO, "Sucessfully initiated server");
    Logger::log(INFO, "Server is listening on port " + std::to_string(mPort) + " with password " + mServerPassword);
    Logger::log(DEBUG, "Port : " + std::to_string(mPort));
    Logger::log(DEBUG, "Password : " + mServerPassword);

    return true;
}

void Server::run()
{

    // [2021-01-01 12:00:00]
    mServerStartTime = time(NULL);

    Logger::log(INFO, "Server is running...");
    mServerLastPingTime = time(NULL);

    // List of the events that returned from kevent
    std::vector<struct kevent> filteredEvents;
    filteredEvents.resize(256);

    // Main loop for server
    // it will run until server is stopped and check event for every 1 second
    timespec serverTick;
    serverTick.tv_nsec = 0;
    serverTick.tv_sec = 0;
    while (true)
    {
        // Logger::log(DEBUG, "Server is waiting for event...");
        const int eventCount = kevent(mhKqueue, NULL, 0, filteredEvents.data(), filteredEvents.size(), &serverTick);
        if (KQUEUE_ERROR == eventCount)
        {
            Logger::log(FATAL, "Failed to get event from kqueue");
            std::perror("kevent");
            close(mServerListenSocket);
            assert(0);
            exit(1);
        }
        // Logger::log(DEBUG, "Server got " + std::to_string(eventCount) + " events");

        // Resize the buffer when the events are occupying most of the buffer.
        const size_t filteredEventsResizeThreshold = 50;
        if (filteredEvents.size() < eventCount + filteredEventsResizeThreshold)
        {
            Logger::log(WARNING, "Event vector is too small, resizing...");
            filteredEvents.resize(filteredEvents.size() * 2);
            // calculate memory size to killo, megabyte, gigabyte
            // 1. sizeof(struct kevent) * mEventVector.size()
            const size_t size = sizeof(struct kevent) * filteredEvents.size();
            if (size < 1024)
                Logger::log(WARNING, "Event vector resized, Current size : " + std::to_string(size) + " bytes");
            else if (size < 1024 * 1024)
                Logger::log(WARNING, "Event vector resized, Current size : " + std::to_string(size / 1024) + " kilobytes");
            else if (size < 1024 * 1024 * 1024)
                Logger::log(WARNING, "Event vector resized, Current size : " + std::to_string(size / 1024 / 1024) + " megabytes");
            else
                Logger::log(WARNING, "Event vector resized, Current size : " + std::to_string(size / 1024 / 1024 / 1024) + " gigabytes");
        }

        // Handle events
        for (size_t i = 0; i < eventCount; i++)
        {
            if (filteredEvents[i].flags & EV_ERROR)
            {
                Logger::log(ERROR, "Error occured in kqueue");
                std::perror("kevent");
                close(mServerListenSocket);
                assert(0);
                exit(1);
            }
            else if (filteredEvents[i].flags & EV_EOF)
            {
                Logger::log(DEBUG, "EOF occured in kqueue, closing client socket and deleting clientData object");
                std::perror("kevent");

                // Find the clientData
                Logger::log(DEBUG, "Finding clientData object");
                ClientData* clientData = mFdToClientGlobalMap[filteredEvents[i].ident]; // cuz it's map, it's O(logN)
                delete clientData;
                Logger::log(DEBUG, "ClientData object deleted");
                mFdToClientGlobalMap.erase(filteredEvents[i].ident);
                Logger::log(DEBUG, "Client removed from map");
                close(filteredEvents[i].ident);
                Logger::log(DEBUG, "Client socket closed");
                // assert(0);
            }
            else if (filteredEvents[i].flags & EVFILT_READ)
            {
                // New client is trying to connect
                if (static_cast<int>(filteredEvents[i].ident) == mServerListenSocket)
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
                    if (KQUEUE_ERROR == kevent(mhKqueue, &newClientEvent, 1, NULL, 0, NULL))
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


                    // it's same as mFdToClientGlobalMap.insert(std::pair<SOCKET_FD, ClientData*>(newClientSocket, newClientData));
                    Logger::log(DEBUG, "Adding new clientData object to map");
                    mFdToClientGlobalMap[newClientSocket] = newClientData;
                    Logger::log(DEBUG, "New clientData object added to map");
                }

                // Client is trying to send message
                else
                {
                    Logger::log(DEBUG, "Client is trying to send message");
                    Logger::log(DEBUG, "Finding clientData object");
                    
                    // Find the clientData
                    // TODO: Change to find() instead of operator[] for preventing creating new ClientData object when not found
                    ClientData* clientData = mFdToClientGlobalMap[filteredEvents[i].ident];
                    if (clientData == NULL)
                    {
                        Logger::log(ERROR, "ClientData not found, closing socket");
                        close(filteredEvents[i].ident);
                        assert(0);
                        continue;
                    }
                    Logger::log(DEBUG, "ClientData object found");

                    // Recv message from client
                    Logger::log(DEBUG, "Receiving data from client");
                    char data[MAX_MESSAGE_LENGTH];
                    int dataLength = recv(filteredEvents[i].ident, data, MAX_MESSAGE_LENGTH, 0);
                    if (SOCKET_ERROR == dataLength)
                    {
                        Logger::log(ERROR, "Failed to receive data from client");
                        std::perror("recv");
                        close(filteredEvents[i].ident);
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

                    // Client disconnected
                    if (dataLength == 0)
                    {
                        Logger::log(INFO, "Client disconnected");

                        Logger::log(DEBUG, "-----------------------------------------");
                        Logger::log(DEBUG, "NickName : " + clientData->getClientNickname());
                        Logger::log(DEBUG, "IP : " + std::string(inet_ntoa(clientData->getClientAddress().sin_addr)));
                        Logger::log(DEBUG, "Port : " + std::to_string(ntohs(clientData->getClientAddress().sin_port)));
                        Logger::log(DEBUG, "-----------------------------------------");

                        // Delete clientData object
                        delete clientData;
                        mFdToClientGlobalMap.erase(filteredEvents[i].ident);
                        close(filteredEvents[i].ident);
                        Logger::log(DEBUG, "ClientData object deleted");
                        continue;
                    }

                    // Handle message
                    // Push message to message Queue with it's clientData information
                    Logger::log(DEBUG, "Pushing message to serverDataQueue");
                    mClientRecvMsgQueue.push(std::pair<SOCKET_FD, std::string>(filteredEvents[i].ident, std::string(data, dataLength)));

                }
            }
        }

        // Pass messages to MessageHandler after handling all events
        {

            // TODO : implement ping
            if (time(NULL) - mServerLastPingTime > SERVER_PING_INTERVAL)
            {
                // TODO : ping clients and kick if not received in 2 seconds
                mServerLastPingTime = time(NULL);
            }

            // TODO : push messages to clients
            // we must check message's validity, hence we need to parse it, and store it in the clientData object
            while (!mClientRecvMsgQueue.empty())
            {
                // send data to MessageHandler, and it will handle the message and request to server
                std::pair<SOCKET_FD, std::string>& data = mClientRecvMsgQueue.front();
                assembleDataToMessage(data);
                mClientRecvMsgQueue.pop();
            }
        }
    }
}

bool Server::setPortAndPassFromArgv(int argc, char** argv)
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
    std::map<SOCKET_FD, ClientData*>::const_iterator clientDataIter = mFdToClientGlobalMap.find(data.first);
    if (clientDataIter == mFdToClientGlobalMap.end())
    {
        Logger::log(ERROR, "ClientData not found\n");
        return;
    }
    ClientData* clientData = (*clientDataIter).second;

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