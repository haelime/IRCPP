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

    mIsRunning = true;
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
                // TODO : if send is done successfully, remove EVFILT_WRITE event

                // Server can send message to client
                Logger::log(INFO, "Server sending message to client");
                Logger::log(DEBUG, "Finding clientData object");

                SOCKET_FD clientFD = filteredEvents[i].ident;

                std::map<SOCKET_FD, ClientData*>::const_iterator clientDataIter = mFdToClientGlobalMap.find(clientFD);

                ClientData* clientData = (*clientDataIter).second;
                if (clientData == NULL)
                {
                    Logger::log(ERROR, "ClientData not found, closing socket");
                    close(clientFD);
                    assert(0);
                    continue;
                }
                Logger::log(DEBUG, "ClientData object found");

                // Send message to client
                Logger::log(DEBUG, "Sending message : " + clientData->getServerToClientSendQueue().front().mMessageVector[0]);
                std::string sendMsg = clientData->getServerToClientSendQueue().front().mMessageVector[0] + "\r\n";
                int sendMsgLength = send(clientFD, sendMsg.c_str(), sendMsg.length(), 0);

                if (SOCKET_ERROR == sendMsgLength)
                {
                    Logger::log(ERROR, "Failed to send message to client");
                    std::perror("send");
                    close(clientFD);
                    assert(0);
                    continue;
                }

                Logger::log(INFO, "Server sent message : " + sendMsg);

                // Pop message from queue
                clientData->getServerToClientSendQueue().pop();

                // Remove EVFILT_WRITE event
                // struct kevent newSendEvent;
                // memset(&newSendEvent, 0, sizeof(newSendEvent));
                // newSendEvent.ident = clientFD;
                // newSendEvent.filter = EVFILT_WRITE;
                // newSendEvent.flags = EV_DISABLE;
                // newSendEvent.data = 0;
                // newSendEvent.udata = NULL;
                // kevent(mhKqueue, &newSendEvent, 1, NULL, 0, NULL);

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
                SOCKET_FD clientFD = mClientRecvProcessQueue.front();
                Logger::log(DEBUG, "Parsing received message to clientData object");

                std::map<SOCKET_FD, ClientData*>::const_iterator clientDataIter = mFdToClientGlobalMap.find(clientFD);
                if (clientDataIter == mFdToClientGlobalMap.end())
                {
                    Logger::log(ERROR, "ClientData not found, closing socket");
                    close(clientFD);
                    assert(0);
                    continue;
                }
                ClientData* clientData = (*clientDataIter).second;
                while (parseReceivedRequestFromClientData(clientFD) == true)
                {
                    Logger::log(DEBUG, "Message parsed successfully");
                    // This logic Takes O(log N), probably can optimize it

                    struct kevent newSendEvent;
                    memset(&newSendEvent, 0, sizeof(newSendEvent));
                    newSendEvent.ident = clientFD;
                    newSendEvent.filter = EVFILT_WRITE;
                    newSendEvent.flags = EV_ENABLE;
                    newSendEvent.data = 0;
                    newSendEvent.udata = NULL;
                    kevent(mhKqueue, &newSendEvent, 1, NULL, 0, NULL);

                    Logger::log(DEBUG, "Executing parsed message to clientData object");
                    executeParsedMessages(clientData);
                }
                mClientRecvProcessQueue.pop();
            }

        }
    }
}

void Server::executeParsedMessages(ClientData* clientData)
{
    // SOCKET_FD clientFD = clientData->getClientSocket();
    std::map<std::string, ClientData*>::const_iterator nickIter;
    while (!clientData->getExecuteMessageQueue().empty())
    {
        Message messageToExecute = clientData->getExecuteMessageQueue().front();
        size_t commandStartPos = 0;
        size_t paramStartPos = 1;
        if (messageToExecute.mHasPrefix) // TODO : fix with this position
        {
            commandStartPos++;
            paramStartPos++;
        }

        // send message to client with kqueue
        Message errMessageToClient;
        Message successMessageToClient;
        std::vector <std::string> channelNames;
        std::vector <std::string> channelKeys;
        std::map<std::string, Channel*>::iterator globalChannelIter;
        size_t posStart;
        size_t posEnd;
        // for cross-validation, i implemented simple parse check here
        // if parse part is done, gonna cross-check with the clientData object
        switch (messageToExecute.mCommand)
        {
        case NONE:

            break;
        case PASS:
            // The PASS command is used to set a 'connection password'.  The
            // optional password can and MUST be set before any attempt to register
            // the connection is made.  Currently this requires that user send a
            // PASS command before sending the NICK/USER combination.
            // The password can and MUST be set before any attempt to register the
            // connection is made.  If a PASS command has been sent and a NICK
            // command is not received in the same session, a nick name of "anonymous"
            // SHOULD be assigned.

            // When PASS is done, response back with NOTICE AUTH :*** Looking up your hostname...

            Logger::log(INFO, "Client Successfully sent PASS command and authenticated");

            successMessageToClient.mCommand = NOTICE;
            successMessageToClient.mMessageVector.clear();
            successMessageToClient.mMessageVector.push_back("NOTICE");
            successMessageToClient.mMessageVector.push_back("AUTH");
            successMessageToClient.mMessageVector.push_back(":*** Looking up your hostname...");
            clientData->getServerToClientSendQueue().push(successMessageToClient);

            break;

        case NICK:

            //  If the server recieves an identical NICK from a client which is
            //  directly connected, it may issue an ERR_NICKCOLLISION to the local
            //  client, drop the NICK command, and not generate any kills.
            Logger::log(DEBUG, "executing NICK command from " + getIpFromClientData(clientData) + " with nickname " + messageToExecute.mMessageVector[0]);
            
            successMessageToClient.mCommand = NONE;
            successMessageToClient.mMessageVector.clear();
            successMessageToClient.mMessageVector.push_back(RPL_PASSACCEPTED);
            successMessageToClient.mMessageVector.push_back("Password accepted");
            clientData->getServerToClientSendQueue().push(successMessageToClient);

            clientData->setClientNickname(messageToExecute.mMessageVector[paramStartPos]);
            Logger::log(INFO, "Client " + clientData->getClientNickname() + " set nickname to " + messageToExecute.mMessageVector[0]);
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
            Logger::log(DEBUG, "executing USER command from");
            Server::logClientData(clientData);

            successMessageToClient.mCommand = NONE;
            successMessageToClient.mMessageVector.clear();
            successMessageToClient.mMessageVector.push_back(RPL_PASSACCEPTED);
            successMessageToClient.mMessageVector.push_back("Password accepted");
            clientData->getServerToClientSendQueue().push(successMessageToClient);

            clientData->setUsername(messageToExecute.mMessageVector[paramStartPos]);
            clientData->setHostname(messageToExecute.mMessageVector[paramStartPos + 1]);
            clientData->setServername(messageToExecute.mMessageVector[paramStartPos + 2]);
            clientData->setRealname(messageToExecute.mMessageVector[paramStartPos + 3]);

            Logger::log(INFO, "Client " + clientData->getClientNickname() + " set username to " + messageToExecute.mMessageVector[paramStartPos]);
            Logger::log(INFO, "Client " + clientData->getClientNickname() + " set hostname to " + messageToExecute.mMessageVector[paramStartPos + 1]);
            Logger::log(INFO, "Client " + clientData->getClientNickname() + " set servername to " + messageToExecute.mMessageVector[paramStartPos + 2]);
            Logger::log(INFO, "Client " + clientData->getClientNickname() + " set realname to " + messageToExecute.mMessageVector[paramStartPos + 3]);

            Server::logClientData(clientData);
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

            Logger::log(DEBUG, "executing JOIN command from");
            Server::logClientData(clientData);
            Server::logMessage(messageToExecute);

            // channels and keys are separated by ','
            // add channel to channelNames vector
            Logger::log(DEBUG, "Parsing channel names and keys");
            posStart = 0;
            posEnd = messageToExecute.mMessageVector[paramStartPos].find(',');
            while (posEnd != std::string::npos)
            {
                std::string channelName = messageToExecute.mMessageVector[paramStartPos].substr(posStart, posEnd);
                if (channelName.length() == 0)
                {
                    Logger::log(ERROR, "Channel name is empty, sending ERR_NEEDMOREPARAMS");
                    errMessageToClient.mMessageVector.push_back(ERR_NEEDMOREPARAMS);
                    errMessageToClient.mMessageVector.push_back("Channel name is empty");
                    clientData->getServerToClientSendQueue().push(errMessageToClient);
                    Server::logClientData(clientData);
                    return;
                }else if (channelName.length() > MAX_CHANNEL_NAME_LENGTH)
                {
                    Logger::log(ERROR, "Channel name is too long, sending ERR_NOSUCHCHANNEL");
                    errMessageToClient.mMessageVector.push_back(ERR_NOSUCHCHANNEL);
                    errMessageToClient.mMessageVector.push_back("Channel name is too long");
                    clientData->getServerToClientSendQueue().push(errMessageToClient);
                    Server::logClientData(clientData);
                    return;
                }
                channelNames.push_back(channelName);
                posStart = posEnd + 1;
                posEnd = messageToExecute.mMessageVector[paramStartPos].find(',', posStart);
            }
            // add last channel to channelNames vector
            {
                std::string channelName = messageToExecute.mMessageVector[paramStartPos].substr(posStart, posEnd);
                if (channelName.length() == 0)
                {
                    Logger::log(ERROR, "Channel name is empty, sending ERR_NEEDMOREPARAMS");
                    errMessageToClient.mMessageVector.push_back(ERR_NEEDMOREPARAMS);
                    errMessageToClient.mMessageVector.push_back("Channel name is empty");
                    clientData->getServerToClientSendQueue().push(errMessageToClient);
                    Server::logClientData(clientData);
                    return;
                }
                else if (channelName.length() > MAX_CHANNEL_NAME_LENGTH)
                {
                    Logger::log(ERROR, "Channel name is too long, sending ERR_NOSUCHCHANNEL");
                    errMessageToClient.mMessageVector.push_back(ERR_NOSUCHCHANNEL);
                    errMessageToClient.mMessageVector.push_back("Channel name is too long");
                    clientData->getServerToClientSendQueue().push(errMessageToClient);
                    Server::logClientData(clientData);
                    return;
                }
                channelNames.push_back(channelName);
            }

            if (channelNames.size() > 0)
            {
                Logger::log(DEBUG, "Channel names parsed");
                for (size_t i = 0; i < channelNames.size(); i++)
                {
                    Logger::log(DEBUG, "Channel name : " + channelNames[i]);
                }
            }
            else
            {
                Logger::log(WARNING, "No channel names, sending ERR_NEEDMOREPARAMS");
                errMessageToClient.mMessageVector.push_back(ERR_NEEDMOREPARAMS);
                errMessageToClient.mMessageVector.push_back("No channel names");
                clientData->getServerToClientSendQueue().push(errMessageToClient);
                Server::logClientData(clientData);
                return;
            }
            // if there is key parameter, add it to channelKeys Vector
            if (messageToExecute.mMessageVector.size() == paramStartPos + 2)
            {
                Logger::log(DEBUG, "Parsing channel keys");
                posStart = 0;
                posEnd = messageToExecute.mMessageVector[paramStartPos + 1].find(',');
                while (posEnd != std::string::npos)
                {
                    std::string channelKey = messageToExecute.mMessageVector[paramStartPos + 1].substr(posStart, posEnd);
                    if (channelKey.length() == 0)
                    {
                        Logger::log(ERROR, "Channel key is empty, sending ERR_NEEDMOREPARAMS");
                        errMessageToClient.mMessageVector.push_back(ERR_NEEDMOREPARAMS);
                        errMessageToClient.mMessageVector.push_back("Channel key is empty");
                        clientData->getServerToClientSendQueue().push(errMessageToClient);
                        Server::logClientData(clientData);
                        return;
                    }
                    else if (channelKey.length() > MAX_CHANNEL_KEY_LENGTH)
                    {
                        Logger::log(ERROR, "Channel key is too long, sending ERR_BADCHANNELKEY");
                        errMessageToClient.mMessageVector.push_back(ERR_BADCHANNELKEY);
                        errMessageToClient.mMessageVector.push_back("Channel key is too long");
                        clientData->getServerToClientSendQueue().push(errMessageToClient);
                        Server::logClientData(clientData);
                        return;
                    }
                    channelKeys.push_back(channelKey);
                    posStart = posEnd + 1;
                    posEnd = messageToExecute.mMessageVector[paramStartPos + 1].find(',', posStart);
                }
                std::string channelKey = messageToExecute.mMessageVector[paramStartPos + 1].substr(posStart, posEnd);
                if (channelKey.length() == 0)
                {
                    Logger::log(ERROR, "Channel key is empty, sending ERR_NEEDMOREPARAMS");
                    errMessageToClient.mMessageVector.push_back(ERR_NEEDMOREPARAMS);
                    errMessageToClient.mMessageVector.push_back("Channel key is empty");
                    clientData->getServerToClientSendQueue().push(errMessageToClient);
                    Server::logClientData(clientData);
                    return;
                }
                else if (channelKey.length() > MAX_CHANNEL_KEY_LENGTH)
                {
                    Logger::log(ERROR, "Channel key is too long, sending ERR_BADCHANNELKEY");
                    errMessageToClient.mMessageVector.push_back(ERR_BADCHANNELKEY);
                    errMessageToClient.mMessageVector.push_back("Channel key is too long");
                    clientData->getServerToClientSendQueue().push(errMessageToClient);
                    Server::logClientData(clientData);
                    return;
                }
                channelKeys.push_back(channelKey);
            }
            if (channelKeys.size() > 0)
            {
                Logger::log(DEBUG, "Channel keys parsed");
                for (size_t i = 0; i < channelNames.size(); i++)
                {
                    Logger::log(DEBUG, "Channel name : " + channelNames[i]);
                    if (channelKeys.size() > i)
                        Logger::log(DEBUG, "With Channel key : " + channelKeys[i]);
                }
            }
            else
            {
                Logger::log(DEBUG, "No channel keys");
            }
            

            Logger ::log(DEBUG, "Adding client to channels");

            for (size_t i = 0; i < channelNames.size(); i++)
            {
                if (channelKeys.size() > i && channelKeys[i].length() > 0)
                {
                    Logger::log(DEBUG, "Channel " + channelNames[i] + " has key " + channelKeys[i]);
                }
                else
                {
                    Logger::log(DEBUG, "Channel " + channelNames[i] + " has no key");
                }

                globalChannelIter = mNameToChannelGlobalMap.find(messageToExecute.mMessageVector[paramStartPos]);
                if (globalChannelIter == mNameToChannelGlobalMap.end())
                {
                    Logger::log(DEBUG, "Channel not found, creating new channel");
                    Channel* newChannel = new Channel(channelNames[i]);
                    mNameToChannelGlobalMap[channelNames[i]] = newChannel;
                    newChannel->setOperatorClient(clientData);
                    if (channelKeys.size() > i)
                    {
                        newChannel->setPassword(channelKeys[i]);
                        connectClientDataWithChannel(clientData, newChannel, channelKeys[i]);
                        Logger::log(INFO, "Channel created with password");
                        Logger::log(INFO, clientData->getClientNickname() + "joined Channel " + newChannel->getName() + " with password");
                        Server::logClientData(clientData);
                        continue;
                    }
                    connectClientDataWithChannel(clientData, newChannel);
                    Logger::log(INFO, "Channel created without password");
                    Logger::log(INFO, clientData->getClientNickname() + "joined Channel " + newChannel->getName() + " with password");
                    Server::logClientData(clientData);
                }
                else
                {
                    Channel* channel = (*globalChannelIter).second;

                    if (channel->getNickToClientDataMap().find(clientData->getClientNickname()) != channel->getNickToClientDataMap().end())
                    {
                        Logger::log(ERROR, "Client is already in the channel, sending ERR_ALREADYINCHANNEL");
                        errMessageToClient.mMessageVector.push_back(ERR_ALREADYINCHANNEL);
                        errMessageToClient.mMessageVector.push_back("Client is already in the channel");
                        clientData->getServerToClientSendQueue().push(errMessageToClient);
                        return;
                    }

                    if (channel->getPassword().length() > 0)
                    {
                        if (channelKeys.size() > i && channelKeys[i] == channel->getPassword())
                        {
                            connectClientDataWithChannel(clientData, channel, channelKeys[i]);

                            successMessageToClient.mCommand = NONE;
                            successMessageToClient.mMessageVector.clear();
                            successMessageToClient.mMessageVector.push_back(RPL_TOPIC);
                            successMessageToClient.mMessageVector.push_back(channel->getName());
                            successMessageToClient.mMessageVector.push_back(channel->getTopic());
                            clientData->getServerToClientSendQueue().push(successMessageToClient);
                            Logger::log(INFO, clientData->getClientNickname() + "joined Channel " + channel->getName() + " with password");
                            Server::logClientData(clientData);
                            continue;
                        }
                        else
                        {
                            Logger::log(WARNING, "Invalid password, sending ERR_BADCHANNELKEY");
                            errMessageToClient.mMessageVector.push_back(ERR_BADCHANNELKEY);
                            errMessageToClient.mMessageVector.push_back("Invalid password");
                            clientData->getServerToClientSendQueue().push(errMessageToClient);
                            continue;
                        }
                    }

                    connectClientDataWithChannel(clientData, channel);

                    successMessageToClient.mCommand = NONE;
                    successMessageToClient.mMessageVector.clear();
                    successMessageToClient.mMessageVector.push_back(RPL_TOPIC);
                    successMessageToClient.mMessageVector.push_back(channel->getName());
                    successMessageToClient.mMessageVector.push_back(channel->getTopic());
                    clientData->getServerToClientSendQueue().push(successMessageToClient);

                    Logger::log(INFO, clientData->getClientNickname() + "joined Channel " + channel->getName());
                    Server::logClientData(clientData);
                }
            }

            break;
        case PART:

            // ERR_NEEDMOREPARAMS              ERR_NOSUCHCHANNEL
            // ERR_NOTONCHANNEL

            // Examples:

            // PART #twilight_zone             ; leave channel "#twilight_zone"

            // PART #oz-ops,&group5            ; leave both channels "&group5" and
            //                                 "#oz-ops".





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

        case NOTICE: // < it's not in the RFC 1459, but it's in the RFC 2812, ONLY SERVER CAN USE THIS COMMAND

            break;

        }
        clientData->getExecuteMessageQueue().pop();
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
        // assert(false);
        return false;
    }
    ClientData* clientData = (*clientDataIter).second;


    // should erase and setReceivedString() if the message has been parsed
    std::string str = clientData->getReceivedString();

    Message messageToExecute;

    Logger::log(DEBUG, "Trying to parse message with : \"" + str + "\"");
    if (str.length() < 2)
    {
        Logger::log(WARNING, "Message is not completed yet");
        Server::logMessage(messageToExecute);
        // assert(false);
        return false;
    }
    else if (str.length() == 2 && str[0] == '\r' && str[1] == '\n')
    {
        Logger::log(WARNING, "Empty message");
        Server::logMessage(messageToExecute);
        // assert(false);
        return false;
    }

    // Logger::log(DEBUG, "Printing str : ");
    // logHasStrCRLF(str); // DEBUG

    std::string target("\r\n");
    std::size_t startPos = 0;
    std::size_t endPos = str.find(target);
    if (endPos == std::string::npos)
    {
        Logger::log(WARNING, "Message is not completed yet");
        Server::logMessage(messageToExecute);
        // assert(false);
        return false;
    }

    size_t commandStartPos = 0;

    // Push back strings to messageToExecute's vector and erase it from the string
    if (endPos != std::string::npos)
    {
        // ends with CRLF
        std::string messageStr = str.substr(startPos, endPos - startPos);

        // we should chunk the messageStr with ' ' and ':' for parsing
        std::string token;
        std::size_t tokenStartPos = 0;
        std::size_t tokenEndPos = messageStr.find(' ', tokenStartPos);
        while (tokenEndPos != std::string::npos)
        {
            token = messageStr.substr(tokenStartPos, tokenEndPos - tokenStartPos);
            messageToExecute.mMessageVector.push_back(token);
            tokenStartPos = tokenEndPos + 1;
            tokenEndPos = messageStr.find(' ', tokenStartPos);
        }
        token = messageStr.substr(tokenStartPos, messageStr.length() - tokenStartPos);
        messageToExecute.mMessageVector.push_back(token);

        // set clientData's receivedString
        str.erase(startPos, endPos - startPos + 2);
        Logger::log(DEBUG, "Erasing message from clientData's receivedString");
        Logger::log(DEBUG, "ClientData's receivedString : " + str);
        clientData->setReceivedString(str);
    }

    // check if the messageToExecute has prefix, it's always a NICKNAME
    if (messageToExecute.mMessageVector[0][0] == ':')
    {
        // checking Nickname's validity
        if (messageToExecute.mMessageVector[0].length() < 2)
        {
            Logger::log(WARNING, "Invalid messageToExecute");
            Server::logMessage(messageToExecute);
            Logger::log(WARNING, "Sending ERR_UNKNOWNCOMMAND");
            Message errMessageToClient;
            errMessageToClient.mMessageVector.push_back(ERR_UNKNOWNCOMMAND);
            errMessageToClient.mMessageVector.push_back("Unknown command");
            clientData->getServerToClientSendQueue().push(errMessageToClient);
            assert(false);
            return false;
        }
        std::string nick = messageToExecute.mMessageVector[0].substr(1, messageToExecute.mMessageVector[0].length() - 1);
        if (mNickToClientGlobalMap.find(nick) != mNickToClientGlobalMap.end())
        {
            Logger::log(WARNING, "Nickname collision, sending ERR_NICKCOLLISION");
            Message errMessageToClient;
            errMessageToClient.mMessageVector.push_back(ERR_NICKCOLLISION);
            errMessageToClient.mMessageVector.push_back("Nickname collision");
            clientData->getServerToClientSendQueue().push(errMessageToClient);
            assert(false);
            return false;
        }
        messageToExecute.mHasPrefix = true;
        commandStartPos = 1;
    }

    // check if the messageToExecute is valid
    if (!isValidMessage(messageToExecute))
    {
        Logger::log(WARNING, "Invalid messageToExecute");
        Server::logMessage(messageToExecute);
        Logger::log(WARNING, "Sending ERR_UNKNOWNCOMMAND");
        Message errMessageToClient;
        errMessageToClient.mMessageVector.push_back(ERR_UNKNOWNCOMMAND);
        errMessageToClient.mMessageVector.push_back("Unknown command");
        clientData->getServerToClientSendQueue().push(errMessageToClient);
        // assert(false);
        return false;
    }

    // Damn, Should we use map for this?
    if (messageToExecute.mMessageVector[commandStartPos] == "PASS")
    {
        messageToExecute.mCommand = PASS;
        if (messageToExecute.mMessageVector.size() != 2)
        {
            Logger::log(WARNING, "Invalid messageToExecute, PASS command must have 1 parameter");
            Server::logMessage(messageToExecute);
            Message errMessageToClient;
            errMessageToClient.mMessageVector.push_back(ERR_NEEDMOREPARAMS);
            errMessageToClient.mMessageVector.push_back("PASS");
            errMessageToClient.mMessageVector.push_back("Not enough parameters");

            clientData->getServerToClientSendQueue().push(errMessageToClient);
            assert(false);
            return false;
        }
        // <user>       ::= <nonwhite> { <nonwhite> }
        // <letter>     ::= 'a' ... 'z' | 'A' ... 'Z'
        // <number>     ::= '0' ... '9'
        // <special>    ::= '-' | '[' | ']' | '\' | '`' | '^' | '{' | '}'
        // <nonwhite>   ::= <any 8bit code except SPACE (0x20)>

        if (mServerPassword == "" || mServerPassword == messageToExecute.mMessageVector[commandStartPos + 1])
        {
            Logger::log(INFO, "Client passed password");
            Logger::log(DEBUG, "Sending RPL_PASSACCEPTED");

            Message errMessagetoClient;
            errMessagetoClient.mMessageVector.push_back(RPL_PASSACCEPTED);
            errMessagetoClient.mMessageVector.push_back("Password accepted");

            clientData->getServerToClientSendQueue().push(errMessagetoClient);
            clientData->getExecuteMessageQueue().push(messageToExecute);
            return true;
        }
        else if (messageToExecute.mMessageVector[commandStartPos + 1] != mServerPassword)
        {
            Logger::log(WARNING, "Invalid password, disconnecting client");
            Server::logMessage(messageToExecute);
            Message errMessageToClient;
            errMessageToClient.mMessageVector.push_back(ERR_PASSWDMISMATCH);
            errMessageToClient.mMessageVector.push_back("Password Missmatched, disconnecting...");

            delete clientData;
            mFdToClientGlobalMap.erase(clientFD);
            close(clientFD);
            Logger::log(DEBUG, "Client disconnected");

            clientData->getServerToClientSendQueue().push(errMessageToClient);
            assert(false);
            return false;
        }
    }
    else if (messageToExecute.mMessageVector[commandStartPos] == "NICK")
    {
        if (messageToExecute.mMessageVector.size() == commandStartPos)
        {
            Logger::log(WARNING, "Invalid messageToExecute");
            Server::logMessage(messageToExecute);
            Message errMessageToClient;
            errMessageToClient.mMessageVector.push_back(ERR_NEEDMOREPARAMS);
            errMessageToClient.mMessageVector.push_back("NICK");
            errMessageToClient.mMessageVector.push_back("Not enough parameters");

            clientData->getServerToClientSendQueue().push(errMessageToClient);
            assert(false);
            return false;
        }
        std::map<std::string, ClientData*>::iterator nickIter;
        nickIter = mNickToClientGlobalMap.find(messageToExecute.mMessageVector[commandStartPos + 1]);
        if (nickIter != mNickToClientGlobalMap.end())
        {
            Logger::log(WARNING, "Nickname collision, sending ERR_NICKCOLLISION");
            Server::logMessage(messageToExecute);
            Message errMessageToClient;
            errMessageToClient.mMessageVector.push_back(ERR_NICKCOLLISION);
            errMessageToClient.mMessageVector.push_back("Nickname collision");

            clientData->getServerToClientSendQueue().push(errMessageToClient);
            assert(false);
            return false;
        }
        messageToExecute.mCommand = NICK;
        clientData->getExecuteMessageQueue().push(messageToExecute);
        return true;
    }
    else if (messageToExecute.mMessageVector[commandStartPos] == "USER")
    {
        if (messageToExecute.mMessageVector.size() != 5)
        {
            Logger::log(WARNING, "Invalid messageToExecute");
            Server::logMessage(messageToExecute);
            Message errMessageToClient;
            errMessageToClient.mMessageVector.push_back(ERR_NEEDMOREPARAMS);
            errMessageToClient.mMessageVector.push_back("USER");
            errMessageToClient.mMessageVector.push_back("Not enough parameters");
            clientData->getServerToClientSendQueue().push(errMessageToClient);
            assert(false);
            return false;
        }

        // check if the user is already registered
        if (clientData->getUsername().length() != 0 || clientData->getHostname().length() != 0 || clientData->getServername().length() != 0 || clientData->getRealname().length() != 0)
        {
            Logger::log(WARNING, "User is already registered, sending ERR_ALREADYREGISTRED");
            Server::logMessage(messageToExecute);
            // send ERR_ALREADYREGISTRED
            Message errMessageToClient;
            errMessageToClient.mMessageVector.push_back(ERR_ALREADYREGISTRED);
            errMessageToClient.mMessageVector.push_back("User is already registered");
            clientData->getServerToClientSendQueue().push(errMessageToClient);
            assert(false);
            return false;
        }
        messageToExecute.mCommand = USER;
        clientData->getExecuteMessageQueue().push(messageToExecute);
        return true;
    }
    else if (messageToExecute.mMessageVector[commandStartPos] == "JOIN")
    {
        if (messageToExecute.mMessageVector.size() == commandStartPos)
        {
            Logger::log(WARNING, "Invalid messageToExecute");
            Server::logMessage(messageToExecute);
            Message errMessageToClient;
            errMessageToClient.mMessageVector.push_back(ERR_NEEDMOREPARAMS);
            errMessageToClient.mMessageVector.push_back("JOIN");
            errMessageToClient.mMessageVector.push_back("Not enough parameters");
            clientData->getServerToClientSendQueue().push(errMessageToClient);
            // assert(false);
            return false;
        }

        messageToExecute.mCommand = JOIN;
        clientData->getExecuteMessageQueue().push(messageToExecute);
        return true;
    }
    // args : <channel>{,<channel>} [<key>{,<key>}]
    else if (messageToExecute.mMessageVector[commandStartPos] == "PART")
    {
        if (messageToExecute.mMessageVector.size() == commandStartPos)
        {
            Logger::log(WARNING, "Invalid messageToExecute");
            Server::logMessage(messageToExecute);
            Message errMessageToClient;
            errMessageToClient.mMessageVector.push_back(ERR_NEEDMOREPARAMS);
            errMessageToClient.mMessageVector.push_back("PART");
            errMessageToClient.mMessageVector.push_back("Not enough parameters");

            clientData->getServerToClientSendQueue().push(errMessageToClient);
            assert(false);
            return false;
        }

        if (messageToExecute.mMessageVector[1] == "")
        {
            Logger::log(WARNING, "Invalid messageToExecute");
            Server::logMessage(messageToExecute);
            Message errMessageToClient;
            errMessageToClient.mMessageVector.push_back(ERR_NEEDMOREPARAMS);
            errMessageToClient.mMessageVector.push_back("PART");
            errMessageToClient.mMessageVector.push_back("Not enough parameters");

            clientData->getServerToClientSendQueue().push(errMessageToClient);
            assert(false);
            return false;
        }

        messageToExecute.mCommand = PART;
        clientData->getExecuteMessageQueue().push(messageToExecute);
        return true;
    }
    else if (messageToExecute.mMessageVector[commandStartPos] == "PRIVMSG")
    {
        messageToExecute.mCommand = PRIVMSG;
        clientData->getExecuteMessageQueue().push(messageToExecute);
        return true;
    }
    else if (messageToExecute.mMessageVector[commandStartPos] == "PING")
    {
        messageToExecute.mCommand = PING;
        clientData->getExecuteMessageQueue().push(messageToExecute);
        return true;
    }
    else if (messageToExecute.mMessageVector[commandStartPos] == "PONG")
    {
        messageToExecute.mCommand = PONG;
        clientData->getExecuteMessageQueue().push(messageToExecute);
        return true;
    }
    else if (messageToExecute.mMessageVector[commandStartPos] == "QUIT")
    {
        messageToExecute.mCommand = QUIT;
        clientData->getExecuteMessageQueue().push(messageToExecute);
        return true;
    }
    else if (messageToExecute.mMessageVector[commandStartPos] == "KICK")
    {
        messageToExecute.mCommand = KICK;
        clientData->getExecuteMessageQueue().push(messageToExecute);
        return true;
    }
    else if (messageToExecute.mMessageVector[commandStartPos] == "INVITE")
    {
        messageToExecute.mCommand = INVITE;
        clientData->getExecuteMessageQueue().push(messageToExecute);
        return true;
    }
    else if (messageToExecute.mMessageVector[commandStartPos] == "TOPIC")
    {
        messageToExecute.mCommand = TOPIC;
        clientData->getExecuteMessageQueue().push(messageToExecute);
        return true;
    }
    else if (messageToExecute.mMessageVector[commandStartPos] == "MODE")
    {
        messageToExecute.mCommand = MODE;
        clientData->getExecuteMessageQueue().push(messageToExecute);
        return true;
    }
    else if (messageToExecute.mMessageVector[commandStartPos] == "NOTICE")
    {
        messageToExecute.mCommand = NOTICE;
        clientData->getExecuteMessageQueue().push(messageToExecute);
        return true;
    }
    else
    {
        Logger::log(ERROR, "Invalid command, sending ERR_UNKNOWNCOMMAND");
        Message errMessageToClient;
        errMessageToClient.mMessageVector.push_back(ERR_UNKNOWNCOMMAND);
        errMessageToClient.mMessageVector.push_back("Unknown command");
        clientData->getServerToClientSendQueue().push(errMessageToClient);
        // assert(false);
        return false;
    }

    // clientData->getExecuteMessageQueue().push(messageToExecute);

    return true;
}

// need double-check, please.
bool Server::isValidParameter(char c) const
{
    if (c == ' ' || c == '\0' || c == '\r' || c == '\n')
        return false;
    return true;
}

bool Server::isValidMessage(const Message& message) const
{
    size_t i = 0;
    if (message.mHasPrefix)
        i++;

    if (message.mMessageVector.size() == 0)
        return false;
    if (message.mMessageVector[0].length() == 0)
        return false;
    // for EXCEPTIONAL CASE : if the message has prefix, the first string must be NICKNAME
    // We know it's not a good way to implement, whatever.
    if (message.mHasPrefix)
    {
        if (message.mMessageVector[0].length() < 2)
            return false;
    }
    while (i < message.mMessageVector.size())
    {
        if (message.mMessageVector[i].length() == 0)
            return false;
        if (message.mMessageVector[i][0] == ':')
            return false;
        if (message.mMessageVector[i].length() > MAX_MESSAGE_LENGTH)
            return false;
        for (size_t j = 0; j < message.mMessageVector[i].length(); j++)
        {
            if (!isValidParameter(message.mMessageVector[i][j]))
                return false;
        }
        i++;
    }
    return true;
}

void Server::logClientData(ClientData* clientData) const
{
    Logger::log(DEBUG, "--------------- Beggining Client Data --------------");
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
    Logger::log(DEBUG, "< End Of Joined Channel List >");
    Logger::log(DEBUG, "================ End of Client Data ================");
}

const std::string Server::getIpFromClientData(ClientData* clientData) const
{
    return std::string(inet_ntoa(clientData->getClientAddress().sin_addr));
}

void Server::logHasStrCRLF(const std::string& str)
{
    bool found = 0;
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

void Server::connectClientDataWithChannel(ClientData* clientData, Channel* channel)
{
    // add clientData to channel
    channel->getNickToClientDataMap().insert(std::pair<std::string, ClientData*>(clientData->getClientNickname(), clientData));
    // add channel to clientData
    clientData->getConnectedChannels().insert(std::pair<std::string, Channel*>(channel->getName(), channel));
}

void Server::connectClientDataWithChannel(ClientData* clientData, Channel* channel, const std::string& password)
{
    if (channel->getPassword() == password)
    {
        channel->getNickToClientDataMap().insert(std::pair<std::string, ClientData*>(clientData->getClientNickname(), clientData));
        // add channel to clientData
        clientData->getConnectedChannels().insert(std::pair<std::string, Channel*>(channel->getName(), channel));
    }
}

void Server::logMessage(const Message& message) const
{
    Logger::log(DEBUG, "----------------- Beggining Message ----------------");
    Logger::log(DEBUG, "Command : " + ValToString(message.mCommand));
    Logger::log(DEBUG, "Has Prefix : " + ValToString(message.mHasPrefix));
    Logger::log(DEBUG, "Message Vector : ");
    for (size_t i = 0; i < message.mMessageVector.size(); i++)
    {
        Logger::log(DEBUG, message.mMessageVector[i]);
    }
    Logger::log(DEBUG, "================== End of Message ==================");
}