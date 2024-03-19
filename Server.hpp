#pragma once

#include <arpa/inet.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <unistd.h>

#include <iostream>
#include <string>
#include <vector>

#include "Client.hpp"

#define SOCKET_ERROR (-1)

class Server
{
public:
    Server() {};
    ~Server() {};

    bool isValidArgv(int argc, char** argv);
    void printUsage(char** argv)
    {
        std::cerr << "Usage : " << argv[0] << " <port> <password>\n";
    };

    void init_server(int port, std::string password)
    {
        // make socket FD
        mServerListenSocket = socket(PF_INET, SOCK_STREAM, 0);
        if (SOCKET_ERROR == mServerListenSocket)
        {
            std::perror("socket");
            exit(1);
        }

        // set Server's address
        mServerAddress.sin_addr.s_addr = INADDR_ANY;
        mServerAddress.sin_port = htons(port);
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
        if (mhKq == -1)
        {
            std::perror("kqueue");
            close(mServerListenSocket);
            exit(1);
        }

        struct kevent event;
        event.ident = mServerListenSocket;
        event.filter = EVFILT_READ;
        event.flags = EV_ADD;
        event.data = 0;
        event.udata = NULL;

        timespec timespecInf;
        timespecInf.tv_nsec = 0;
        timespecInf.tv_sec = 0;

        // kevent returns number of events placed in the eventlist
        if (SOCKET_ERROR == kevent(mhKq, &event, 1, NULL, 0, &timespecInf))
        {
            std::perror("kevent");
            close(mServerListenSocket);
            exit(1);
        }

        // Actual Loop of Server
        while (true)
        {
            // Check for new events, but do not register new events with
            // the kqueue. Hence the 2nd and 3rd arguments are NULL, 0.
            // Only handle 1 new event per iteration in the loop; 5th
            // argument is 1.
            int new_events = kevent(mhKq, NULL, 0, &event, 1, NULL);
            if (SOCKET_ERROR == new_events)
            {
                std::perror("kevent loop");
                close(mServerListenSocket);
            }

        }



        mServerPassword = password;
    }

private:
    int mServerListenSocket;
    sockaddr_in mServerAddress;
    socklen_t mServerAddressLength;

    std::string mServerPassword;

    int mhKq;

    // key is socket, value is Client, which contains all the information
    // when a new client connects, a new Client object is created and added
    // when a client disconnects, the Client object is deleted
    std::map<int, Client*> mClients;
};