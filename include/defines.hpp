#pragma once

#define MAX_PASSWORD_LENGTH (256)
#define MAX_PORT_NUMBER (65535)

#define MAX_EVENTS (1024)
#define MAX_MESSAGE_LENGTH (512)
#define MAX_NICKNAME_LENGTH (9)
#define MAX_CHANNEL_NAME_LENGTH (200)

// 60 seconds
#define SERVER_PING_INTERVAL (60)
#define SERVER_PING_TIMEOUT (SERVER_PING_INTERVAL * 2)

#define ERR_NICKCOLLISION "433"
#define ERR_NONICKNAMEGIVEN "431"
#define ERR_ERRONEUSNICKNAME "432"

#define ERR_NEEDMOREPARAMS "461"
#define ERR_ALREADYREGISTRED "462"
           
#define ERR_BANNEDFROMCHAN "474"
#define ERR_INVITEONLYCHAN "473"
#define ERR_BADCHANNELKEY "475"
#define ERR_CHANNELISFULL "471"
#define ERR_BADCHANMASK "476"
#define ERR_NOSUCHCHANNEL "403" 
#define ERR_TOOMANYCHANNELS "405"
#define RPL_TOPIC "332"
