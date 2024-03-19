#pragma once

#include <string>
#include <map>
#include "Channel.hpp"

class Client
{
    public:

    private:
        // Client's nickname, empty if not set
        std::string nickname;
        // Client's socket
        int socket;
        // Client's IP
        std::string ip;
        // Client's port
        int port;
        // Client's status
        bool status;
        // Client's last message
        std::string lastMessageTime;
        // Client's last message status

        std::map <std::string, Chennel *> mChannels;
};