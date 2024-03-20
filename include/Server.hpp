#pragma once

#include <arpa/inet.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <unistd.h>

#include <iostream>
#include <string>
#include <vector>
#include <utility>

#include "Client.hpp"

#define SOCKET_FD (int)
#define KQUEUE_FD (int)
#define SOCKET_ERROR (-1)

#define MAX_PASSWORD_LENGTH (256)
#define MAX_PORT_NUMBER (65535)

#define MAX_EVENTS (1024)
#define MAX_MESSAGE_LENGTH (512)
#define MAX_NICKNAME_LENGTH (9)

class Server
{
public:
    Server() {};
    ~Server() {};

    bool checkAndSetArgv(int argc, char** argv)
    {
        // ./ircserc 9999 asdf
        if (argc != 3)
            return false;

        // if not digit
        for (int i = 0; argv[1] != NULL; i++)
        {
            if (!isdigit(argv[1][i]))
                return false;
        }

        mPort = atoi(argv[1]);
        if (mPort > MAX_PORT_NUMBER || mPort < 0)
            return false;

        mServerPassword = argv[1];
        if (mServerPassword.length() > MAX_PASSWORD_LENGTH)
            return false;


        return true;
    };

    void printUsage(char** argv)
    {
        std::cerr << "Usage : " << argv[0] << " <port> <password>\n";
    };

    void init_server(void)
    {
        // make socket FD
        mServerListenSocket = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

        if (SOCKET_ERROR == mServerListenSocket)
        {
            std::perror("socket");
            exit(1);
        }

        // set Server's address
        mServerAddress.sin_addr.s_addr = INADDR_ANY;
        mServerAddress.sin_port = htons(mPort);
        mServerAddress.sin_family = AF_INET;
        mServerAddress.sin_len = sizeof(mServerAddress);
        mServerAddressLength = mServerAddress.sin_len;

        // bind server's address & port
        if (SOCKET_ERROR == bind(mServerListenSocket, (const sockaddr*)&mServerAddress,
            mServerAddressLength))
        {
            std::perror("bind");
            close(mServerListenSocket);
            exit(1);
        }

        // start listening on port
        if (SOCKET_ERROR == listen(mServerListenSocket, SOMAXCONN))
        {
            std::perror("listen");
            close(mServerListenSocket);
            exit(1);
        }

        // init kq
        mhKq = kqueue();
        if (SOCKET_ERROR == mhKq)
        {
            std::perror("kqueue");
            close(mServerListenSocket);
            exit(1);
        }

        // add event filter
        struct kevent mEvent;
        mEvent.ident = mServerListenSocket; // trace this socket
        mEvent.filter = EVFILT_READ; // when read event occurs
        mEvent.flags = EV_ADD; // add event, if it's already added, it will be ignored
        mEvent.data = 0; // it means Filter-specific data value
        mEvent.udata = NULL; // no user data

        // is it nessasary? IDK but it's fast enough
        memset(&mEventBuffer, 0, sizeof(mEventBuffer));

        std::cout << "Server is initiating on port " << mPort << " with password " << mServerPassword << "\n";
    }

    void run()
    {
        timespec timespecInf;
        timespecInf.tv_nsec = 0;
        timespecInf.tv_sec = 0;

        // kevent returns number of events placed in the eventlist
        if (SOCKET_ERROR == kevent(mhKq, &mEvent, 1, NULL, 0, &timespecInf))
        {
            std::perror("kevent");
            close(mServerListenSocket);
            exit(1);
        }

        // main loop for server
        while (true)
        {
            // kevent returns number of events placed in the eventlist
            int eventCount = kevent(mhKq, NULL, 0, mEventBuffer, 1024, &timespecInf);
            if (SOCKET_ERROR == eventCount)
            {
                std::perror("kevent");
                close(mServerListenSocket);
                exit(1);
            }

            if (eventCount != 0)
            {
                // handle events
                for (int i = 0; i < eventCount; i++)
                {
                    // if it's read event and it's server socket, it means client is trying to connect
                    if (mEventBuffer[i].flags & EVFILT_READ)
                    {
                        // if it's server socket, it means new client is trying to connect
                        if (mEventBuffer[i].ident == mServerListenSocket)
                        {
                            sockaddr_in newClientAddress;
                            socklen_t newClientAddressLength = sizeof(newClientAddress);
                            SOCKET_FD newClientSocket = accept(mServerListenSocket, (sockaddr*)&newClientAddress, &newClientAddressLength);
                            fnctrl(newClientSocket, F_SETFL, O_NONBLOCK);
                            if (SOCKET_ERROR == newClientSocket)
                            {
                                std::perror("accept");
                                close(mServerListenSocket);
                                exit(1);
                            }

                            // add new client to kqueue
                            struct kevent newClientEvent;
                            newClientEvent.ident = newClientSocket;
                            newClientEvent.filter = EVFILT_READ;
                            newClientEvent.flags = EV_ADD;
                            newClientEvent.data = 0;
                            newClientEvent.udata = NULL;
                            if (SOCKET_ERROR == kevent(mhKq, &newClientEvent, 1, NULL, 0, &timespecInf))
                            {
                                std::perror("kevent newClientEvent");
                                close(mServerListenSocket);
                                close(newClientSocket);
                                exit(1);
                            }

                            // create new client object
                            Client* newClient = new Client(newClientAddress);

                            // it's same as mClients.insert(std::pair<SOCKET_FD, Client*>(newClientSocket, newClient));
                            mClients[newClientSocket] = newClient;
                        }

                        // if it's not server socket, it means client is trying to send message
                        else
                        {
                            // find the client
                            Client* client = mClients[mEventBuffer[i].ident]; // cuz it's map, it's O(logN)
                            if (client == NULL)
                            {
                                std::cerr << "Client not found, closing socket\n";
                                close(mEventBuffer[i].ident);
                                continue;
                            }

                            // get message from client
                            char message[MAX_MESSAGE_LENGTH];
                            int messageLength = recv(mEventBuffer[i].ident, message, MAX_MESSAGE_LENGTH, 0);
                            if (SOCKET_ERROR == messageLength)
                            {
                                std::perror("recv");
                                close(mEventBuffer[i].ident);
                                continue;
                            }

                            // if message is empty, it means client disconnected
                            if (messageLength == 0)
                            {
                                // delete client object
                                delete client;
                                mClients.erase(mEventBuffer[i].ident);
                                close(mEventBuffer[i].ident);
                                continue;
                            }

                            // handle message
                            // push message to message Queue with it's client information
                            mServerMessageQueue.push(std::pair<SOCKET_FD, std::string>(mEventBuffer[i].ident, std::string(message)));
                        }

                    }
                }
            }
            // if there is no event, we can push messages to clients
            else
            {
                // TODO : push messages to clients
                // we must check message's validity, hence we need to parse it, and store it in the client object
                while (!mServerMessageQueue.empty())
                {
                    std::pair<SOCKET_FD, std::string> message = mServerMessageQueue.front();
                    mServerMessageQueue.pop();

                    // find the client
                    Client* client = mClients[message.first]; // cuz it's map, it's O(logN)
                    if (client == NULL)
                    {
                        std::cerr << "Client not found, closing socket\n";
                        close(message.first);
                        continue;
                    }

                    // handle message
                    // parse message and store it in the client object, if it is valid message then push it to the chennel's message queue


                }
                continue;
            }
        }





    }

private:

    // server network data
private:
    SOCKET_FD mServerListenSocket;
    sockaddr_in mServerAddress;
    socklen_t mServerAddressLength;

    KQUEUE_FD mhKq;
    struct kevent mEvent;

    // key is socket, value is Client, which contains all the information about the client
    // when a new client connects, a new Client object is created and added
    // when a client disconnects, the Client object is deleted


// arguments
private:
    int mPort;
    std::string mServerPassword;

// server data
private:
    // Client has is's channel information, so we don't need to store channel information in server
    std::map<SOCKET_FD, Client*> mClients;
    std::map<std::string, Channel*> mChannels;

    std::queue<std::pair<SOCKET_FD, std::string>> mServerMessageQueue;
    struct kevent mEventBuffer[1024];

    time_t mServerStartTime;
    time_t mServerLastPingTime; // to kick if not received in 2 seconds
};