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
    bool mHasPrefix;
    std::string mPrefix;

    Command mCommand;
    // TODO : check parameter's max size
    std::vector <std::string> mParams;
};
