#pragma once

#include <string>
#include <vector>

enum Command
{
    NONE = 0,
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
    NOTICE, // <- it's similar with PRIVMSG. no need to implement but, just in case
};

struct Message
{
    Message() : mHasPrefix(false), mCommand(NONE) {};
    
    bool mHasPrefix;

    Command mCommand;
    // TODO : check parameter's max size
    std::vector <std::string> mMessageTokens;
};
