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

#define MAX_PASSWORD_LENGTH (256)
#define MAX_PORT_NUMBER (65535)
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
        mServerListenSocket = socket(PF_INET, SOCK_STREAM, 0);

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

        // is it nessasary? IDK
        memset(&mEventBuffer, 0, sizeof(mEventBuffer));

        std::cout << "Server is running on port " << mPort << " with password " << mServerPassword << "\n";
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

        
        if (mEventBuffer[0].flags & EV_EOF)
        {
            std::cout << "Client disconnected\n";
            close(mEventBuffer[0].ident);
        }
        else
        {
            std::cout << "Client connected\n";
            Client* client = new Client(mEventBuffer[0].ident);
            mClients.push_back(client);
        }

        


    }

// server network data
private:
    int mServerListenSocket;
    sockaddr_in mServerAddress;
    socklen_t mServerAddressLength;

    int mhKq;
    struct kevent mEvent;

    // key is socket, value is Client, which contains all the information
    // when a new client connects, a new Client object is created and added
    // when a client disconnects, the Client object is deleted
    std::map<int, Client*> mClients;


// arguments
private:
    int mPort;
    std::string mServerPassword;
    
private:
    std::vector<Client*> mClients;

    struct kevent mEventBuffer[1024];
};