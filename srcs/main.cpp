
#include "Server.hpp"
#include "ClientData.hpp"
#include "Channel.hpp"
#include "SignalHandler.hpp"

// You must be able to authenticate, set a nickname, a username, join a channel,
// send and receive private messages using your reference client.
// ◦ All the messages sent from one client to a channel have to be forwarded to
// every other client that joined the channel.
// ◦ You must have operators and regular users.
// ◦ Then, you have to implement the commands that are specific to channel
// operators:
// KICK - Eject a client from the channel
// INVITE - Invite a client to a channel
// TOPIC - Change or view the channel topic
// MODE - Change the channel’s mode:
// · i: Set/remove Invite-only channel
// · t: Set/remove the restrictions of the TOPIC command to channel
// operators
// · k: Set/remove the channel key (password)
// · o: Give/take channel operator privilege
// 5
// ft_irc Internet Relay Chat
// · l: Set/remove the user limit to channel
int main (int argc, char **argv)
{
    Server server;

    SignalHandler::setSignals(server);
    Logger::setConsoleLogging(true); 
    Logger::setFileLogging("IrcServer.log");
    Logger::setLogLevel(INFO | WARNING | ERROR | FATAL | DEFAULT);

    if (server.initServer(argc, argv) == false)
    {
        Logger::log(ERROR, "Server initialization failed");
        return 1;
    }
    server.run();

    return 0;
}