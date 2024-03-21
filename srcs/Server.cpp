#include <fcntl.h>
#include "Server.hpp"
#include "ClientData.hpp"
#include "Channel.hpp"
#include "Logger.hpp"

void Server::init_server(void)
{
    // make socket FD
    mServerListenSocket = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    Logger::log(INFO, "Server is creating socket...");
    if (SOCKET_ERROR == mServerListenSocket)
    {
        Logger::log(FATAL, "Failed to create socket");
        std::perror("socket");
        assert(0);
        exit(1);
    }
    Logger::log(INFO, "Server created socket");

    // set Server's address
    mServerAddress.sin_addr.s_addr = INADDR_ANY;
    mServerAddress.sin_port = htons(mPort);
    mServerAddress.sin_family = AF_INET;
    mServerAddress.sin_len = sizeof(mServerAddress);
    mServerAddressLength = mServerAddress.sin_len;

    // bind server's address & port
    Logger::log(INFO, "Server is binding socket...");
    if (SOCKET_ERROR == bind(mServerListenSocket, (const sockaddr*)&mServerAddress,
        mServerAddressLength))
    {
        Logger::log(FATAL, "Failed to bind socket");
        std::perror("bind");
        close(mServerListenSocket);
        assert(0);
        exit(1);
    }
    Logger::log(INFO, "Server binded socket");

    // start listening on port
    Logger::log(INFO, "Server is listening on socket...");
    if (SOCKET_ERROR == listen(mServerListenSocket, SOMAXCONN))
    {
        Logger::log(FATAL, "Failed to listen on socket");
        std::perror("listen");
        close(mServerListenSocket);
        assert(0);
        exit(1);
    }

    // init kq
    Logger::log(INFO, "Server is creating kqueue...");
    mhKq = kqueue();
    if (SOCKET_ERROR == mhKq)
    {
        Logger::log(FATAL, "Failed to create kqueue");
        std::perror("kqueue");
        close(mServerListenSocket);
        assert(0);
        exit(1);
    }
    Logger::log(INFO, "Server created kqueue");

    // add event filter
    
    mEvent.ident = mServerListenSocket; // trace this socket
    mEvent.filter = EVFILT_READ; // when read event occurs
    mEvent.flags = EV_ADD; // add event, if it's already added, it will be ignored
    mEvent.data = 0; // it means Filter-specific data value
    mEvent.udata = NULL; // no user data


    // is it nessasary? IDK but it's fast enough
    mEventVector.reserve(256);

    Logger::log(INFO, "Server is initiating...");


    // kevent returns number of events placed in the eventlist
    if (KQUEUE_ERROR == kevent(mhKq, &mEvent, 1, NULL, 0, NULL))
    {
        Logger::log(FATAL, "Failed to add event to kqueue");
        std::perror("kevent");
        close(mServerListenSocket);
        assert(0);
        exit(1);
    }

    Logger::log(INFO, "");
    std::cout << "Sucessfully initiated server on port " << ANSI_YELLOW << mPort << ANSI_RESET << " with password " << ANSI_YELLOW << mServerPassword << ANSI_RESET << std::endl;
}

void Server::run()
{
    // to wait for event infinitely or just for 0 seconds
    // timespec timespecInf;
    // timespecInf.tv_nsec = 0;
    // timespecInf.tv_sec = 0;

    // [2021-01-01 12:00:00]
    mServerStartTime = time(NULL);
    std::tm* startTime = std::localtime(&mServerStartTime);
    std::stringstream ss;
    ss << "[" << startTime->tm_year + 1900 << "-" << startTime->tm_mon + 1 << "-" << startTime->tm_mday << " " << startTime->tm_hour << ":" << startTime->tm_min << ":" << startTime->tm_sec << "] ";
    std::string timeString = ss.str();

    Logger::log(INFO, "");
    std::cout << "Server started at " << ANSI_YELLOW << timeString << ANSI_RESET << std::endl;
    mServerLastPingTime = time(NULL);

    // main loop for server
    while (true)
    {
        // kevent returns number of events placed in the eventlist
        int eventCount = kevent(mhKq, NULL, 0, &mEventVector[0], mEventVector.size(), NULL);
        if (KQUEUE_ERROR == eventCount)
        {
            Logger::log(FATAL, "Failed to get event from kqueue");
            std::perror("kevent");
            close(mServerListenSocket);
            assert(0);
            exit(1);
        }

        // handle events
        for (int i = 0; i < eventCount; i++)
        {
            if (mEventVector[i].flags & EVFILT_READ)
            {
                // new client is trying to connect
                if (static_cast<int>(mEventVector[i].ident) == mServerListenSocket)
                {
                    sockaddr_in newClientAddress;
                    socklen_t newClientAddressLength = sizeof(newClientAddress);
                    SOCKET_FD newClientSocket = accept(mServerListenSocket, (sockaddr*)&newClientAddress, &newClientAddressLength);
                    if (SOCKET_ERROR == newClientSocket)
                    {
                        Logger::log(FATAL, "Failed to accept new client");
                        std::perror("accept");
                        close(mServerListenSocket);
                        assert(0);
                        exit(1);
                    }

                    if (fcntl(newClientSocket, F_SETFL, O_NONBLOCK) == -1)
                    {
                        Logger::log(FATAL, "Failed to set non-blocking socket");
                        std::perror("fcntl");
                        close(mServerListenSocket);
                        close(newClientSocket);
                        assert(0);
                        exit(1);
                    }

                    // add new clientData to kqueue
                    struct kevent newClientEvent;
                    newClientEvent.ident = newClientSocket;
                    newClientEvent.filter = EVFILT_READ;
                    newClientEvent.flags = EV_ADD;
                    newClientEvent.data = 0;
                    newClientEvent.udata = NULL;
                    if (KQUEUE_ERROR == kevent(mhKq, &newClientEvent, 1, NULL, 0, NULL))
                    {
                        Logger::log(FATAL, "Failed to add new client to kqueue");
                        std::perror("kevent newClientEvent");
                        close(mServerListenSocket);
                        close(newClientSocket);
                        assert(0);
                        exit(1);
                    }

                    // create new clientData object
                    ClientData* newClientData = new ClientData(newClientAddress);

                    // it's same as mClientDataMap.insert(std::pair<SOCKET_FD, ClientData*>(newClientSocket, newClientData));
                    mClientDataMap[newClientSocket] = newClientData;
                }

                // if it's not server socket, it means client is trying to send message
                else
                {
                    // find the clientData
                    ClientData* clientData = mClientDataMap[mEventVector[i].ident]; // cuz it's map, it's O(logN)
                    if (clientData == NULL)
                    {
                        Logger::log(ERROR, "ClientData not found, closing socket");
                        std::cerr << "ClientData not found, closing socket\n";
                        close(mEventVector[i].ident);
                        assert(0);
                        continue;
                    }

                    // get message from client
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

                    // if message is empty, it means client disconnected
                    if (dataLength == 0)
                    {
                        Logger::log(INFO, "Client disconnected");
                        // delete clientData object
                        delete clientData;
                        mClientDataMap.erase(mEventVector[i].ident);
                        close(mEventVector[i].ident);
                        continue;
                    }

                    // handle message
                    // push message to message Queue with it's clientData information
                    mServerDataQueue.push(std::pair<SOCKET_FD, std::string>(mEventVector[i].ident, std::string(data)));
                }
            }
        }
        // if there is no event, we can push messages to MessageHandler
        if (eventCount == 0)
        {
            // TODO : push messages to clients
            // we must check message's validity, hence we need to parse it, and store it in the clientData object
            while (!mServerDataQueue.empty())
            {
                // send data to MessageHandler, and it will handle the message and request to server
                std::pair<SOCKET_FD, std::string> &data = mServerDataQueue.front();
                mMessageHandler.assembleDataToMessage(data, mClientDataMap);
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

