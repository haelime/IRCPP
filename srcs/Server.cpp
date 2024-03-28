#include <fcntl.h>
#include "Server.hpp"
#include "ClientData.hpp"
#include "Channel.hpp"
#include "Logger.hpp"
#include "defines.hpp"
#include "types.hpp"

bool Server::initServer(int argc, char** argv)
{
    if (setPortAndPassFromArgv(argc, argv) == false)
    {
        printUsage(argv);
        return false;
    }

    // Create listen socket
    mServerListenSocket = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    Logger::log(DEBUG, "Server is creating socket...");
    if (SOCKET_ERROR == mServerListenSocket)
    {
        Logger::log(FATAL, "Failed to create socket");
        std::perror("socket");
        assert(0);
        return false;
    }
    Logger::log(DEBUG, "Server created socket");

    // Set Server's address
    mServerAddress.sin_addr.s_addr = INADDR_ANY;
    mServerAddress.sin_port = htons(mPort);
    mServerAddress.sin_family = AF_INET;
    mServerAddress.sin_len = sizeof(mServerAddress);
    mServerAddressLength = mServerAddress.sin_len;

    // Bind listen socket
    Logger::log(DEBUG, "Server is binding socket...");
    if (SOCKET_ERROR == bind(mServerListenSocket, (const sockaddr*)&mServerAddress,
        mServerAddressLength))
    {
        Logger::log(FATAL, "Failed to bind socket");
        std::perror("bind");
        close(mServerListenSocket);
        assert(0);
        return false;
    }
    Logger::log(DEBUG, "Server binded socket");

    // Start listening
    Logger::log(DEBUG, "Server is listening on socket...");
    if (SOCKET_ERROR == listen(mServerListenSocket, SOMAXCONN))
    {
        Logger::log(FATAL, "Failed to listen on socket");
        std::perror("listen");
        close(mServerListenSocket);
        assert(0);
        return false;
    }

    // Init kqueue
    Logger::log(DEBUG, "Server is creating kqueue...");
    mhKqueue = kqueue();
    if (SOCKET_ERROR == mhKqueue)
    {
        Logger::log(FATAL, "Failed to create kqueue");
        std::perror("kqueue");
        close(mServerListenSocket);
        assert(0);
        return false;
    }
    Logger::log(DEBUG, "Server created kqueue");

    // Register listen socket to kqueue
    struct kevent evListenEvent;
    evListenEvent.ident = mServerListenSocket; // trace this socket
    evListenEvent.filter = EVFILT_READ; // when read event occurs
    evListenEvent.flags = EV_ADD | EV_ENABLE; // add event, if it's already added, it will be ignored
    evListenEvent.data = 0; // it means Filter-specific data value
    evListenEvent.udata = NULL; // no user data

    Logger::log(DEBUG, "Server is initiating...");

    if (KQUEUE_ERROR == kevent(mhKqueue, &evListenEvent, 1, NULL, 0, NULL))
    {
        Logger::log(FATAL, "Failed to add event to kqueue");
        std::perror("kevent");
        close(mServerListenSocket);
        assert(0);
        return false;
    }

    Logger::log(INFO, "Sucessfully initiated server");
    Logger::log(INFO, "Server is listening on port " + ValToString(mPort) + " with password " + mServerPassword);
    Logger::log(DEBUG, "Port : " + ValToString(mPort));
    Logger::log(DEBUG, "Password : " + mServerPassword);

    return true;
}

void Server::run()
{

    // [2021-01-01 12:00:00]
    mServerStartTime = time(NULL);

    Logger::log(INFO, "Server is running...");
    mServerLastPingTime = time(NULL);

    // List of the events that returned from kevent
    std::vector<struct kevent> filteredEvents;
    filteredEvents.resize(256);

    // Main loop for server
    // it will run until server is stopped and check event for every 1 second
    timespec serverTick;
    serverTick.tv_nsec = 0;
    serverTick.tv_sec = 0;
    while (true)
    {
        // Logger::log(DEBUG, "Server is waiting for event...");
        const int eventCount = kevent(mhKqueue, NULL, 0, filteredEvents.data(), filteredEvents.size(), &serverTick);
        if (KQUEUE_ERROR == eventCount)
        {
            Logger::log(FATAL, "Failed to get event from kqueue");
            std::perror("kevent");
            close(mServerListenSocket);
            assert(0);
            exit(1);
        }
        // Logger::log(DEBUG, "Server got " + ValToString(eventCount) + " events");

        // Resize the buffer when the events are occupying most of the buffer.
        const size_t filteredEventsResizeThreshold = 50;
        if (filteredEvents.size() < eventCount + filteredEventsResizeThreshold)
        {
            Logger::log(WARNING, "Event vector is too small, resizing...");
            filteredEvents.resize(filteredEvents.size() * 2);
            // calculate memory size to killo, megabyte, gigabyte
            // 1. sizeof(struct kevent) * mEventVector.size()
            const size_t size = sizeof(struct kevent) * filteredEvents.size();
            if (size < 1024)
                Logger::log(WARNING, "Event vector resized, Current size : " + ValToString(size) + " bytes");
            else if (size < 1024 * 1024)
                Logger::log(WARNING, "Event vector resized, Current size : " + ValToString(size / 1024) + " kilobytes");
            else if (size < 1024 * 1024 * 1024)
                Logger::log(WARNING, "Event vector resized, Current size : " + ValToString(size / 1024 / 1024) + " megabytes");
            else
                Logger::log(WARNING, "Event vector resized, Current size : " + ValToString(size / 1024 / 1024 / 1024) + " gigabytes");
        }

        // Handle events
        for (int i = 0; i < eventCount; i++)
        {
            if (filteredEvents[i].flags & EV_ERROR)
            {
                Logger::log(ERROR, "Error occured in kqueue");
                std::perror("kevent");
                close(mServerListenSocket);
                assert(0);
                exit(1);
            }
            else if (filteredEvents[i].flags & EV_EOF)
            {
                Logger::log(DEBUG, "EOF occured in kqueue, closing client socket and deleting clientData object");
                std::perror("kevent");

                // Find the clientData
                Logger::log(DEBUG, "Finding clientData object");
                // TODO : change to .find() instead of operator[] for preventing creating new ClientData object when not found
                ClientData* clientData = mFdToClientGlobalMap[filteredEvents[i].ident]; // cuz it's map, it's O(logN)
                delete clientData;
                Logger::log(DEBUG, "ClientData object deleted");
                mFdToClientGlobalMap.erase(filteredEvents[i].ident);
                Logger::log(DEBUG, "Client removed from map");
                close(filteredEvents[i].ident);
                Logger::log(DEBUG, "Client socket closed");
                // assert(0);
            }
            else if (filteredEvents[i].flags & EVFILT_READ)
            {
                // New client is trying to connect
                if (static_cast<int>(filteredEvents[i].ident) == mServerListenSocket)
                {
                    sockaddr_in newClientAddress;
                    socklen_t newClientAddressLength = sizeof(newClientAddress);
                    SOCKET_FD newClientSocket = accept(mServerListenSocket, (sockaddr*)&newClientAddress, &newClientAddressLength);
                    Logger::log(DEBUG, "New client is trying to connect");
                    if (SOCKET_ERROR == newClientSocket)
                    {
                        Logger::log(ERROR, "Failed to accept new client");
                        std::perror("accept");
                        close(mServerListenSocket);
                        assert(0);
                        continue;
                    }

                    Logger::log(INFO, "New client connected");

                    // TODO : change log format
                    Logger::log(DEBUG, "|-----------------------------------------");
                    Logger::log(DEBUG, "SocketDescriptor : " + ValToString(newClientSocket));
                    Logger::log(DEBUG, "IP : " + std::string(inet_ntoa(newClientAddress.sin_addr)));
                    Logger::log(DEBUG, "Client's Port : " + ValToString(ntohs(newClientAddress.sin_port)));
                    Logger::log(DEBUG, "-----------------------------------------|");

                    Logger::log(DEBUG, "Setting non-blocking socket");
                    if (fcntl(newClientSocket, F_SETFL, O_NONBLOCK) == -1)
                    {
                        Logger::log(ERROR, "Failed to set non-blocking socket");
                        Logger::log(ERROR, "Aborting...");
                        std::perror("fcntl");
                        close(mServerListenSocket);
                        close(newClientSocket);
                        assert(0);
                        exit(1);
                    }
                    Logger::log(DEBUG, "Socket set to non-blocking");

                    // add new clientData to kqueue
                    struct kevent newClientEvent;
                    memset(&newClientEvent, 0, sizeof(newClientEvent));
                    newClientEvent.ident = newClientSocket;
                    newClientEvent.filter = EVFILT_READ;
                    newClientEvent.flags = EV_ADD;
                    newClientEvent.data = 0;
                    newClientEvent.udata = NULL;

                    Logger::log(DEBUG, "Adding new client to kqueue");
                    if (KQUEUE_ERROR == kevent(mhKqueue, &newClientEvent, 1, NULL, 0, NULL))
                    {
                        Logger::log(ERROR, "Failed to add new client to kqueue");
                        Logger::log(ERROR, "Aborting...");
                        std::perror("kevent newClientEvent");
                        close(mServerListenSocket);
                        close(newClientSocket);
                        assert(0);
                        exit(1);
                    }
                    Logger::log(DEBUG, "New client added to kqueue");

                    // create new clientData object
                    Logger::log(DEBUG, "Creating new clientData object");
                    ClientData* newClientData = new ClientData(newClientAddress);
                    Logger::log(DEBUG, "New clientData object created");
                    newClientData->setClientSocket(newClientSocket);
                    std::string ip = inet_ntoa(newClientAddress.sin_addr);
                    newClientData->setIp(ip);
                    Logger::log(DEBUG, "New clientData object address : " + ip);


                    // it's same as mFdToClientGlobalMap.insert(std::pair<SOCKET_FD, ClientData*>(newClientSocket, newClientData));
                    Logger::log(DEBUG, "Adding new clientData object to map");
                    mFdToClientGlobalMap.insert(std::pair<SOCKET_FD, ClientData*>(newClientSocket, newClientData));
                    mFdToClientGlobalMap[newClientSocket] = newClientData;
                    Logger::log(DEBUG, "New clientData object added to map");
                }

                // Client is trying to send message
                else
                {
                    Logger::log(DEBUG, "Client is trying to send message");
                    Logger::log(DEBUG, "Finding clientData object");

                    // Find the clientData
                    // TODO: Change to find() instead of operator[] for preventing creating new ClientData object when not found
                    ClientData* clientData = mFdToClientGlobalMap[filteredEvents[i].ident];
                    if (clientData == NULL)
                    {
                        Logger::log(ERROR, "ClientData not found, closing socket");
                        close(filteredEvents[i].ident);
                        assert(0);
                        continue;
                    }
                    Logger::log(DEBUG, "ClientData object found");

                    // Recv message from client
                    Logger::log(DEBUG, "Receiving data from client");
                    char recvMsg[MAX_MESSAGE_LENGTH];
                    int recvMsgLength = recv(filteredEvents[i].ident, recvMsg, MAX_MESSAGE_LENGTH, 0);
                    if (SOCKET_ERROR == recvMsgLength)
                    {
                        Logger::log(ERROR, "Failed to receive data from client");
                        std::perror("recv");
                        close(filteredEvents[i].ident);
                        assert(0);
                        continue;
                    }

                    Logger::log(INFO, clientData->getIp() + " sent message : " + std::string(recvMsg, recvMsgLength));

                    Server::logClientData(clientData);

                    // Client disconnected
                    if (recvMsgLength == 0)
                    {
                        Logger::log(INFO, "Client disconnected");

                        Server::logClientData(clientData);

                        // Delete clientData object
                        delete clientData;
                        mFdToClientGlobalMap.erase(filteredEvents[i].ident);
                        close(filteredEvents[i].ident);
                        Logger::log(DEBUG, "ClientData object deleted");
                        continue;
                    }

                    // Handle message
                    // Push message to message Queue with it's clientData information
                    Logger::log(DEBUG, "Pushing message to serverDataQueue");
                    Server::mClientRecvProcessQueue.push(filteredEvents[i].ident);
                    std::string recvMsgStr(recvMsg, recvMsgLength);
                    clientData->appendReceivedString(recvMsgStr);

                }
            }
            else if (filteredEvents[i].flags & EVFILT_WRITE)
            {
                // Server can send message to client
                Logger::log(DEBUG, "Server sending message to client");
                Logger::log(DEBUG, "Finding clientData object");

                // SOCKET_FD clientFD = filteredEvents[i].ident;


                // std::map<SOCKET_FD, ClientData*>::const_iterator clientDataIter = mFdToClientGlobalMap.find(clientFD);



                // Find the clientData


            }
        }

        // Pass messages to MessageHandler after handling all events
        {

            // TODO : implement ping
            if (time(NULL) - mServerLastPingTime > SERVER_PING_INTERVAL)
            {
                // TODO : ping clients and kick if not received in 2 seconds
                mServerLastPingTime = time(NULL);
            }

            // TODO : push messages to clients
            // we must check message's validity, hence we need to parse it, and store it in the clientData object
            while (!mClientRecvProcessQueue.empty())
            {
                // send receivedRequest to clientData, and server will handle the message
                SOCKET_FD client = mClientRecvProcessQueue.front();
                Logger::log(DEBUG, "Parsing received message to clientData object");
                
                if (parseReceivedRequestFromClientData(client) == true)
                {
                    Logger::log(DEBUG, "Message parsed successfully");
                    SOCKET_FD clientFD = client;
                    // This logic Takes O(log N), probably can optimize it
                    std::map<SOCKET_FD, ClientData*>::const_iterator clientDataIter = mFdToClientGlobalMap.find(clientFD);
                    SOCKET_FD newClientSocket = (*clientDataIter).first;
                    ClientData* clientData = (*clientDataIter).second;

                    struct kevent newSendEvent;
                    memset(&newSendEvent, 0, sizeof(newSendEvent));
                    newSendEvent.ident = newClientSocket;
                    newSendEvent.filter = EVFILT_WRITE;
                    newSendEvent.flags = EV_ADD | EV_ENABLE;
                    newSendEvent.data = 0;
                    newSendEvent.udata = NULL;
                    kevent(mhKqueue, &newSendEvent, 1, NULL, 0, NULL);

                    Logger::log(DEBUG, "Sending parsed message to clientData object");
                    enqueueParsedMessages(clientData);
                }
                mClientRecvProcessQueue.pop();
            }
        }
    }
}

void Server::enqueueParsedMessages(ClientData* clientData)
{ 
    SOCKET_FD clientFD = clientData->getClientSocket();
    std::map<std::string, ClientData*>::const_iterator nickIter;
    while (!clientData->getParsedMessageQueue().empty())
    {
        Message message = clientData->getParsedMessageQueue().front();

        // send message to client with kqueue
        Message errMessage;
        std::vector <std::string> channelNames;
        std::vector <std::string> channelKeys;
        std::map<std::string, Channel*>::const_iterator channelIter = mNameToChannelGlobalMap.find(message.mMessageVector[0]);
        // for cross-validation, i implemented simple parse check here
        // if parse part is done, gonna cross-check with the clientData object
        switch (message.mCommand)
        {
        case PASS:
            // The PASS command is used to set a 'connection password'.  The
            // optional password can and MUST be set before any attempt to register
            // the connection is made.  Currently this requires that user send a
            // PASS command before sending the NICK/USER combination.
            // The password can and MUST be set before any attempt to register the
            // connection is made.  If a PASS command has been sent and a NICK
            // command is not received in the same session, a nick name of "anonymous"
            // SHOULD be assigned.
            if (message.mMessageVector.size() != 1)
            {
                Logger::log(ERROR, "Invalid message, PASS command must have 1 parameter");

                errMessage.mMessageVector.push_back(ERR_NEEDMOREPARAMS);
                errMessage.mMessageVector.push_back("PASS");
                errMessage.mMessageVector.push_back("Not enough parameters");

                clientData->getServerToClientSendQueue().push(errMessage);
                break;
            }
            // <user>       ::= <nonwhite> { <nonwhite> }
            // <letter>     ::= 'a' ... 'z' | 'A' ... 'Z'
            // <number>     ::= '0' ... '9'
            // <special>    ::= '-' | '[' | ']' | '\' | '`' | '^' | '{' | '}'
            // <nonwhite>   ::= <any 8bit code except SPACE (0x20)>

            for (size_t i=0; i<message.mMessageVector[0].length(); i++)
            {
                if (isblank(message.mMessageVector[0][i]) && message.mMessageVector[0][i] != ' ')
                {
                    Logger::log(ERROR, "Invalid password, disconnecting client");
                    errMessage.mMessageVector.push_back(ERR_PASSWDMISMATCH);
                    errMessage.mMessageVector.push_back("Password Missmatched, disconnecting...");

                    clientData->getServerToClientSendQueue().push(errMessage);
                    delete clientData;
                    mFdToClientGlobalMap.erase(clientFD);
                    close(clientFD);
                    Logger::log(DEBUG, "Client disconnected");
                    break;
                }
            }


            if (message.mMessageVector[0] != mServerPassword)
            {
                Logger::log(ERROR, "Invalid password, disconnecting client");
                errMessage.mMessageVector.push_back(ERR_PASSWDMISMATCH);
                errMessage.mMessageVector.push_back("Password Missmatched, disconnecting...");

                clientData->getServerToClientSendQueue().push(errMessage);
                delete clientData;
                mFdToClientGlobalMap.erase(clientFD);
                close(clientFD);
                Logger::log(DEBUG, "Client disconnected");
                break;
            }

            break;
        case NICK:

            //  If the server recieves an identical NICK from a client which is
            //  directly connected, it may issue an ERR_NICKCOLLISION to the local
            //  client, drop the NICK command, and not generate any kills.
            Logger::log(DEBUG, "executing NICK command from " + getIpFromClientData(clientData) + " with nickname " + message.mMessageVector[0]);
            if (message.mMessageVector.size() != 1)
            {
                Logger::log(ERROR, "Invalid message");
                errMessage.mMessageVector.push_back(ERR_NEEDMOREPARAMS);
                errMessage.mMessageVector.push_back("NICK");
                errMessage.mMessageVector.push_back("Not enough parameters");
                clientData->getServerToClientSendQueue().push(errMessage);
                break;
            }
            nickIter = mNickToClientGlobalMap.find(message.mMessageVector[0]);
            if (nickIter != mNickToClientGlobalMap.end())
            {
                Logger::log(ERROR, "Nickname collision, sending ERR_NICKCOLLISION");

                errMessage.mMessageVector.push_back(ERR_NICKCOLLISION);
                errMessage.mMessageVector.push_back("Nickname collision");
                clientData->getServerToClientSendQueue().push(errMessage);    
            }
            clientData->setClientNickname(message.mMessageVector[0]);
            Logger::log(INFO, "Client " + clientData->getClientNickname() + " set nickname to " + message.mMessageVector[0]);
            break;
        case USER:
            //    The USER message is used at the beginning of connection to specify
            //    the username, hostname, servername and realname of s new user.  It is
            //    also used in communication between servers to indicate new user
            //    arriving on IRC, since only after both USER and NICK have been
            //    received from a client does a user become registered.

            //    Between servers USER must to be prefixed with client's NICKname.
            //    Note that hostname and servername are normally ignored by the IRC
            //    server when the USER command comes from a directly connected client
            //    (for security reasons), but they are used in server to server
            //    communication.  This means that a NICK must always be sent to a
            //    remote server when a new user is being introduced to the rest of the
            //    network before the accompanying USER is sent.

            //    It must be noted that realname parameter must be the last parameter,
            //    because it may contain space characters and must be prefixed with a
            //    colon (':') to make sure this is recognised as such.

            //    Since it is easy for a client to lie about its username by relying
            //    solely on the USER message, the use of an "Identity Server" is
            //    recommended.  If the host which a user connects from has such a
            //    server enabled the username is set to that as in the reply from the
            //    "Identity Server".
            if (message.mMessageVector.size() != 4)
            {
                Logger::log(ERROR, "Invalid message");
                break;
            }

            // check if the user is already registered
            if (clientData->getUsername().length() != 0 || clientData->getHostname().length() != 0 || clientData->getServername().length() != 0 || clientData->getRealname().length() != 0)
            {
                Logger::log(ERROR, "User is already registered, sending ERR_ALREADYREGISTRED");
                // send ERR_ALREADYREGISTRED
                errMessage.mMessageVector.push_back (ERR_ALREADYREGISTRED);
                errMessage.mMessageVector.push_back("User is already registered");
                clientData->getServerToClientSendQueue().push(errMessage);
                break;
            }

            clientData->setUsername(message.mMessageVector[0]);
            clientData->setHostname(message.mMessageVector[1]);
            clientData->setServername(message.mMessageVector[2]);
            clientData->setRealname(message.mMessageVector[3]);


            break;
        case JOIN:
            // Parameters: <channel>{,<channel>} [<key>{,<key>}]

            // The JOIN command is used by client to start listening a specific
            // channel. Whether or not a client is allowed to join a channel is
            // checked only by the server the client is connected to; all other
            // servers automatically add the user to the channel when it is received
            // from other servers.  The conditions which affect this are as follows:

            //         1.  the user must be invited if the channel is invite-only;
            //         2.  the user's nick/username/hostname must not match any
            //             active bans;
            //         3.  the correct key (password) must be given if it is set.

            // These are discussed in more detail under the MODE command (see
            // section 4.2.3 for more details).

            // Once a user has joined a channel, they receive notice about all
            // commands their server receives which affect the channel.  This
            // includes MODE, KICK, PART, QUIT and of course PRIVMSG/NOTICE.  The
            // JOIN command needs to be broadcast to all servers so that each server
            // knows where to find the users who are on the channel.  This allows
            // optimal delivery of PRIVMSG/NOTICE messages to the channel.

            // If a JOIN is successful, the user is then sent the channel's topic
            // (using RPL_TOPIC) and the list of users who are on the channel (using
            // RPL_NAMREPLY), which must include the user joining.

            // The JOIN command is also used to join a one-to-one conversation with
            // another user.  To join a channel "#foo", the following message is sent:
           
            // Examples:

            // JOIN #foobar                    ; join channel #foobar.

            // JOIN &foo fubar                 ; join channel &foo using key "fubar".

            // JOIN #foo,&bar fubar            ; join channel #foo using key "fubar"
            //                                 and &bar using no key.

            // JOIN #foo,#bar fubar,foobar     ; join channel #foo using key "fubar".
            //                                 and channel #bar using key "foobar".

            // JOIN #foo,#bar                  ; join channels #foo and #bar.

            // :WiZ JOIN #Twilight_zone        ; JOIN message from WiZ




            for (size_t i = 1; i < message.mMessageVector.size(); i++)
            {
                if (i == 0) // < PASS
                    continue;
                if (message.mMessageVector[i][0] == '#')
                    channelNames.push_back(message.mMessageVector[i]);
                else if (message.mMessageVector[i][0] == '&')
                    channelNames.push_back(message.mMessageVector[i]);
                else
                    channelKeys.push_back(message.mMessageVector[i]);
            }
            
            if (channelIter == mNameToChannelGlobalMap.end())
            {
                Logger::log(DEBUG, "Channel not found, creating new channel");
                Channel* newChannel = new Channel(message.mMessageVector[0]);
                mNameToChannelGlobalMap[message.mMessageVector[0]] = newChannel;
                newChannel->setOperatorClient(clientData);
                // newChannel.
                Logger::log(DEBUG, "Channel created");
            }



            break;
        case PART:

            break;
        case PRIVMSG:

            break;
        case PING:

            break;
        case PONG:

            break;
        case QUIT:

            break;
        case KICK:

            break;
        case INVITE:

            break;

        case TOPIC:

            break;
        case MODE:

            break;

        }
        clientData->getParsedMessageQueue().pop();
    }
}

bool Server::setPortAndPassFromArgv(int argc, char** argv)
{
    // ./ircserc 9999 asdf
    if (argc != 3)
        return false;

    // if not digit
    for (int i = 0; argv[1][i] != '\0'; i++)
    {
        if (!isdigit(argv[1][i]))
            return false;
    }

    mPort = atoi(argv[1]);
    if (mPort > MAX_PORT_NUMBER || mPort < 0)
        return false;

    mServerPassword = argv[2];
    if (mServerPassword.length() > MAX_PASSWORD_LENGTH)
        return false;


    return true;
}

bool Server::parseReceivedRequestFromClientData(SOCKET_FD client)
{
    SOCKET_FD clientFD = client;

    std::map<SOCKET_FD, ClientData*>::const_iterator clientDataIter = mFdToClientGlobalMap.find(clientFD);
    if (clientDataIter == mFdToClientGlobalMap.end())
    {
        Logger::log(ERROR, "ClientData not found\n");
        assert(false);
        return false;
    }
    ClientData* clientData = (*clientDataIter).second;


    // should erase and setReceivedString() if the message has been parsed
    std::string str = clientData->getReceivedString();

    Logger :: log (DEBUG, "Trying to parse message with : \"" + str + "\"");
    if (str.length() < 2)
    {
        Logger::log(WARNING, "Message is not completed yet");
        assert(false);
        return false;
    }
    else if (str.length() == 2 && str[0] == '\r' && str[1] == '\n')
    {
        Logger::log(WARNING, "Empty message");
        assert(false);
        return false;
    }

    Logger::log(DEBUG, "Printing str : ");
    logHasStrCRLF(str);

    std::string target ("\r\n");
    std::size_t pos = str.find(target);
    if (pos == std::string::npos)
    {
        Logger::log(ERROR, "Message is not completed yet");
        assert(false);
        return false;
    }

    




    Message message;

    // parse prefix

    // <message>  ::= [':' <prefix> <SPACE> ] <command> <params> <crlf>
    // <prefix>   ::= <servername> | <nick> [ '!' <user> ] [ '@' <host> ]

    // DON'T BELIVE THIS LOGIC
    if (str[0] == ':')
    {
        size_t spaceIndex = str.find(' ');
        if (spaceIndex == str.npos)
        {
            Logger::log(ERROR, "Invalid message");
            assert(false);
            return false;
        }
        std::string::iterator prefixIter = str.begin() + spaceIndex;

        // cut the prefix
        std::string tmpPrefix = str.substr(1, prefixIter - str.begin());
        str = str.substr(prefixIter - str.begin() + 1);

        if (mNickToClientGlobalMap.find(tmpPrefix) != mNickToClientGlobalMap.end())
        {
            // prefix is ALWAYS nick
            message.mHasPrefix = true;
            message.mMessageVector.push_back(tmpPrefix);
        }
        else
        {
            Logger::log(ERROR, "Invalid prefix");
            assert(false);
            return false;
        }
    }
    else
    {
        message.mHasPrefix = false;
    }

    // Using your reference client with your server must be similar to using it with any
    // official IRC server. However, you only have to implement the following features:
    // ◦ You must be able to authenticate, set a nickname, a username, join a channel,
    // send and receive private messages using your reference client.
    // ◦ All the messages sent from one client to a channel have to be forwarded to
    // every other client that joined the channel.
    // ◦ You must have operators and regular users.
    // ◦ Then, you have to implement the commands that are specific to channel
    // operators:
    // ∗ KICK - Eject a client from the channel
    // ∗ INVITE - Invite a client to a channel
    // ∗ TOPIC - Change or view the channel topic
    // ∗ MODE - Change the channel’s mode:
    // · i: Set/remove Invite-only channel
    // · t: Set/remove the restrictions of the TOPIC command to channel
    // operators
    // · k: Set/remove the channel key (password)
    // · o: Give/take channel operator privilege
    // 5
    // ft_irc Internet Relay Chat
    // · l: Set/remove the user limit to channel
    // parse command

    // size_t spaceIndex = str.find(' ');
    // if (spaceIndex == str.npos)
    // {
    //     Logger::log(ERROR, "Invalid message");
    //     assert(false);
    //     return false;
    // }
    // std::string::iterator commandIter = str.begin() + spaceIndex;

    // // message is already cut by CR LF, so we start from 0
    // std::string commandStr = str.substr(0, commandIter - str.begin());
    // str = str.substr(commandIter - str.begin() + 1);

    // DON'T BELIVE THIS LOGIC
    std::string commandStr;
    // if (std::getline(ss, commandStr, ' '))
    {
        for (size_t i = 0; i < commandStr.length(); i++)
        {
            if (!isValidCommand(commandStr[i]))
            {
                Logger::log(ERROR, "Invalid command : " + commandStr);
                Server::logHasStrCRLF(commandStr);
                assert(false);
                return false;
            }
        }
    }
    // check commandStr
    for (size_t i = 0; i < commandStr.length(); i++)
    {
        if (!isValidCommand(commandStr[i]))
        {
            Logger::log(ERROR, "Invalid command");
            assert(false);
            return false;
        }
    }

    // set command
    // is there any better way to do this? :(
    // should we use command map?
    Command command;
    if (commandStr == "PASS")
        command = PASS;
    else if (commandStr == "NICK")
        command = NICK;
    else if (commandStr == "USER")
        command = USER;
    else if (commandStr == "JOIN")
        command = JOIN;
    else if (commandStr == "PART")
        command = PART;
    else if (commandStr == "PRIVMSG")
        command = PRIVMSG;
    else if (commandStr == "PING")
        command = PING;
    else if (commandStr == "PONG")
        command = PONG;
    else if (commandStr == "QUIT")
        command = QUIT;
    else if (commandStr == "KICK")
        command = KICK;
    else if (commandStr == "INVITE")
        command = INVITE;
    else if (commandStr == "TOPIC")
        command = TOPIC;
    else if (commandStr == "MODE")
        command = MODE;
    else
    {
        Logger::log(ERROR, "Invalid command");
        assert(false);
        return false;
    }

    message.mCommand = command;

    // DON'T BELIVE THIS LOGIC
    // parse params
    std::string params;
    // std::getline(ss, params, '\r');
    // check params and push it to message's params vector
    std::string::iterator paramsIter = params.begin();
    while (paramsIter != params.end())
    {
        size_t spaceIndex = params.find(' ', paramsIter - params.begin());
        std::string::iterator nextParamsIter = params.end();
        if (spaceIndex == params.npos)
        {
            std::string tmpParam = params.substr(paramsIter - params.begin());
            for (size_t i = 0; i < tmpParam.length(); i++)
            {
                if (!isValidParameter(tmpParam[i]))
                {
                    Logger::log(ERROR, "Invalid params");
                    assert(false);
                    return false;
                }
            }
            // TODO : consider emplace_back
            message.mMessageVector.push_back(tmpParam);
            break;
        }
        std::string tmpParam = params.substr(paramsIter - params.begin(), nextParamsIter - paramsIter);
        for (size_t i = 0; i < tmpParam.length(); i++)
        {
            if (!isValidParameter(tmpParam[i]))
            {
                Logger::log(ERROR, "Invalid params");
                assert(false);
                return false;
            }
        }
        message.mMessageVector.push_back(tmpParam);
        paramsIter = nextParamsIter + 1;
    }

    // CONSIDER MULTIPLE MESSAGES
    clientData->getParsedMessageQueue().push(message);

    return true;
}

// need double-check, please.
bool Server::isValidParameter(char c) const
{
    if (c == ' ' || c == '\0' || c == '\r' || c == '\n')
        return false;
    return true;
}

bool Server::isValidMessage(std::string& message) const
{
    for (size_t i = 0; i < message.length(); i++)
    {
        if (message[i] == '\0')
        {
            assert(false);
            return false;
        }
    }
    return true;
}

void Server::logClientData(ClientData* clientData) const
{
    Logger::log(DEBUG, "================= Beggining Client Data ================");
    Logger::log(DEBUG, "NickName : " + clientData->getClientNickname());
    Logger::log(DEBUG, "Username : " + clientData->getUsername());
    Logger::log(DEBUG, "Hostname : " + clientData->getHostname());
    Logger::log(DEBUG, "Servername : " + clientData->getServername());
    Logger::log(DEBUG, "Realname : " + clientData->getRealname());
    Logger::log(DEBUG, "IP : " + std::string(inet_ntoa(clientData->getClientAddress().sin_addr)));
    Logger::log(DEBUG, "Client's Port : " + ValToString(ntohs(clientData->getClientAddress().sin_port)));
    std::string receivedString = clientData->getReceivedString();
    if (receivedString.length() > 0)
        Logger::log(DEBUG, "Received Data : " + clientData->getReceivedString());
    else
        Logger::log(DEBUG, "Received Data : None");
    Logger::log(DEBUG, "< Joined Channel List >");
    std::map<std::string, Channel*> connectedChannelMap = clientData->getConnectedChannels();
    for (std::map<std::string, Channel*>::const_iterator channelIter = connectedChannelMap.begin(); channelIter != connectedChannelMap.end(); channelIter++)
    {
        Logger::log(DEBUG, "Channel : " + channelIter->first);
    }
    Logger::log(DEBUG, "------------------ End of Client Data ------------------");
}

const std::string Server::getIpFromClientData(ClientData *clientData) const
{
    return std::string(inet_ntoa(clientData->getClientAddress().sin_addr));
}

void Server::logHasStrCRLF(const std::string &str)
{
    bool found =0;
    for (size_t i = 0; i < str.length(); i++)
    {
        if (str[i] == '\r')
        {
            Logger::log(DEBUG, str + " has CR");
            found = 1;
        }
        else if (str[i] == '\n')
        {
            Logger::log(DEBUG, str + " has LF");
            found = 1;
        }
    }
    if (!found)
        Logger::log(DEBUG, str + " has no CRLF");
}

bool Server::isValidCommand(char c) const
{
    if (isalnum(c))
        return true;
    return false;
}