#pragma once

#define SERVER_NAME "ircserv"
#define SERVER_VERSION "0.1"

#define MAX_PASSWORD_LENGTH (256)
#define MAX_PORT_NUMBER (65535)

#define MAX_EVENTS (1024)
#define MAX_MESSAGE_LENGTH (512)
#define MAX_NICKNAME_LENGTH (9)
#define MAX_CHANNEL_NAME_LENGTH (200)
#define MAX_PARAM_LENGTH (200)
#define MAX_USERNAME_LENGTH (50)
#define MAX_REALNAME_LENGTH (50)
#define MAX_HOSTNAME_LENGTH (50)
#define MAX_MODE_LENGTH (10)
#define MAX_TOPIC_LENGTH (200)
#define MAX_CHANNEL_KEY_LENGTH (50)

// 60 seconds
#define SERVER_PING_INTERVAL (60)
#define SERVER_PING_TIMEOUT (SERVER_PING_INTERVAL * 2)


typedef std::string ERROR_NUM_STRING;

#define ERR_NOSUCHNICK "401"
#define ERR_NOSUCHSERVER "402"
#define ERR_NOSUCHCHANNEL "403" 
#define ERR_TOOMANYCHANNELS "405"
#define ERR_NORECIPIENT "411"
#define ERR_NOTEXTTOSEND "412"
#define ERR_UNKNOWNCOMMAND "421"
#define ERR_NOMOTD "422"
#define ERR_NONICKNAMEGIVEN "431"
#define ERR_ERRONEUSNICKNAME "432"
#define ERR_NICKCOLLISION "433"
#define ERR_USERNOTINCHANNEL "441"
#define ERR_NOTONCHANNEL "442"
#define ERR_ALREADYINCHANNEL "443"
#define ERR_NOTREGISTERED "451"

#define ERR_NEEDMOREPARAMS "461"
#define ERR_ALREADYREGISTRED "462"
#define ERR_PASSWDMISMATCH "464"
           
#define ERR_CHANNELISFULL "471"
#define ERR_INVITEONLYCHAN "473"
#define ERR_BANNEDFROMCHAN "474"
#define ERR_BADCHANNELKEY "475"
#define ERR_BADCHANMASK "476"
#define ERR_NOCHANMODES "477"
#define ERR_CHANOPRIVSNEEDED "482"

// 001    RPL_WELCOME
//         "Welcome to the Internet Relay Network
//         <nick>!<user>@<host>"
// 002    RPL_YOURHOST
//         "Your host is <servername>, running version <ver>"
// 003    RPL_CREATED
//         "This server was created <date>"
// 004    RPL_MYINFO
//         "<servername> <version> <available user modes>
//         <available channel modes>"

//     - The server sends Replies 001 to 004 to a user upon
//     successful registration.


// 005    RPL_BOUNCE
//         "Try server <server name>, port <port number>"

#define RPL_WELCOME "001"
#define RPL_YOURHOST "002"
#define RPL_CREATED "003"
#define RPL_MYINFO "004"

#define RPL_TOPIC "332"
#define RPL_NOTOPIC "331"
#define RPL_NAMREPLY "353"
#define RPL_ENDOFNAMES "366"
#define RPL_MOTD "372"
#define RPL_MOTDSTART "375"
#define RPL_ENDOFMOTD "376"

#define ERR_USERONCHANNEL "443"

#define ERR_UNKNOWNMODE "472"
#define RPL_CHANNELMODEIS "324"
#define ERR_KEYSET "467"