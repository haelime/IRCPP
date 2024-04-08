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
    QUIT,
    KICK,
    INVITE,
    TOPIC,
    MODE,
    NOTICE, // <- it's similar with PRIVMSG. but only for server to client.
};

struct Message
{
    Message() : mHasPrefix(false), mCommand(NONE) {};
    
    bool mHasPrefix;

    // switch case hint for optimization
    Command mCommand;
    // TODO : check parameter's max size
    std::vector <std::string> mMessageTokens;
};
