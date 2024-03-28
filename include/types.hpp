#pragma once

#include <string>
#include <vector>

enum Command
{
    PASS,
    NICK,
    USER,
    JOIN,
    PART,
    PRIVMSG,
    PING,
    PONG,
    QUIT,
    KICK,
    INVITE,
    TOPIC,
    MODE,
};

struct Message
{
    Message() : mHasPrefix(false) {};
    
    bool mHasPrefix;

    Command mCommand;
    // TODO : check parameter's max size
    std::vector <std::string> mParams;
};
