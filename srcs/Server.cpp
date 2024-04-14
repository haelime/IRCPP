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
        Logger::log(ERROR, "Failed to create socket");
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
        Logger::log(ERROR, "Failed to bind socket");
        Logger::log(ERROR, "Probably port is already in use");
        // std::perror("bind");
        close(mServerListenSocket);
        // assert(0);
        return false;
    }
    Logger::log(DEBUG, "Server binded socket");

    // Start listening
    Logger::log(DEBUG, "Server is listening on socket...");
    if (SOCKET_ERROR == listen(mServerListenSocket, SOMAXCONN))
    {
        Logger::log(ERROR, "Failed to listen on socket");
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
        Logger::log(ERROR, "Failed to create kqueue");
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
        Logger::log(ERROR, "Failed to add event to kqueue");
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
                Logger::log(FATAL, "Error occured in kqueue");
                std::perror("kevent");
                close(mServerListenSocket);
                assert(0);
                exit(1);
            }
            else if (filteredEvents[i].flags & EV_EOF)
            {
                Logger::log(DEBUG, "EOF occured in kqueue, closing client socket and deleting clientData object");

                // Find the clientData
                Logger::log(DEBUG, "Finding clientData object");
                // TODO : change to .find() instead of operator[] for preventing creating new ClientData object when not found
                Server::disconnectClientDataFromServer(mFdToClientGlobalMap[filteredEvents[i].ident]);
                // assert(0);
            }
            else if (filteredEvents[i].filter == EVFILT_READ)
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
                    newClientData->setKqueue(mhKqueue);

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
                    ClientData* clientData = mFdToClientGlobalMap.find(filteredEvents[i].ident)->second;
                    if (clientData == NULL)
                    {
                        Logger::log(WARNING, "ClientData not found");
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
                        Server::disconnectClientDataFromServer(clientData);
                        Logger::log(ERROR, "Client disconnected");
                        continue;
                    }

                    Server::logClientData(clientData);

                    // Client disconnected
                    if (recvMsgLength == 0)
                    {
                        Logger::log(INFO, "Client disconnected");

                        Server::logClientData(clientData);

                        // Delete clientData object
                       Server::disconnectClientDataFromServer(clientData);
                        continue;
                    }

                    if (clientData->getClientNickname().empty())
                    {
                        std::string recvMsgStr(recvMsg, recvMsgLength);
                        if (recvMsgStr.length() > 2 && recvMsgStr[recvMsgStr.length() - 1] == '\n' && recvMsgStr[recvMsgStr.length() - 2] == '\r')
                            Logger::log(RECV, std::string(inet_ntoa(clientData->getClientAddress().sin_addr)) + " : " + std::string(recvMsg, recvMsgLength - 2));
                        else
                            Logger::log(RECV, std::string(inet_ntoa(clientData->getClientAddress().sin_addr)) + " : " + std::string(recvMsg, recvMsgLength));
                    }
                    else
                    {
                        std::string recvMsgStr(recvMsg, recvMsgLength);
                        if (recvMsgStr.length() > 2 && recvMsgStr[recvMsgStr.length() - 1] == '\n' && recvMsgStr[recvMsgStr.length() - 2] == '\r')
                            Logger::log(RECV, clientData->getClientNickname() + " : " + std::string(recvMsg, recvMsgLength - 2));
                        else
                            Logger::log(RECV, clientData->getClientNickname() + " : " + std::string(recvMsg, recvMsgLength));
                    }

                    // Handle message
                    // Push message to message Queue with it's clientData information
                    Logger::log(DEBUG, "Pushing message to serverDataQueue");
                    Server::mRecvedStrPerClientDataProcessQueue.push(filteredEvents[i].ident);
                    std::string recvMsgStr(recvMsg, recvMsgLength);

                    // find non printable character except "\r\n" in message and remove it
                    for (size_t i = 0; i < recvMsgStr.length(); i++)
                    {
                        if ((recvMsgStr[i] < 32 || recvMsgStr[i] > 126) && recvMsgStr[i] != '\r' && recvMsgStr[i] != '\n')
                        {
                            recvMsgStr.erase(i, 1);
                            i--;
                        }
                    }
                    if (recvMsgStr == "\r\n")
                        continue;

                        clientData->appendReceivedString(recvMsgStr);

                }
            }
            else if (filteredEvents[i].filter == EVFILT_WRITE)
            {
                // TODO : if send is done successfully, remove EVFILT_WRITE event

                // Server can send message to client
                // Logger::log(INFO, "Server sending message to client");
                // Logger::log(DEBUG, "Finding clientData object");

                SOCKET_FD clientFD = filteredEvents[i].ident;

                std::map<SOCKET_FD, ClientData*>::const_iterator clientDataIter = mFdToClientGlobalMap.find(clientFD);
                if (clientDataIter == mFdToClientGlobalMap.end())
                {
                    Logger::log(WARNING, "ClientData not found");
                    // assert(0);
                    continue;
                }
                ClientData* clientData = clientDataIter->second;
                if (clientData == NULL)
                {
                    Logger::log(WARNING, "ClientData not found");
                    assert(0);
                    continue;
                }
                
                // Make message to send from message tokens if there is no remaining in sendBuffer
                // :<Server Name> <Message> \r\n

                if (clientData->getSendBuffer().empty())
                {
                    // No exist messages to send
                    if (clientData->getServerToClientSendQueue().empty())
                    {
                        continue;  
                    }

                    std::string sendMsg;
                    if (clientData->getServerToClientSendQueue().front().mHasPrefix == false)
                        sendMsg = ":" + std::string(inet_ntoa(mServerAddress.sin_addr)) + " ";
                    std::vector<std::string> messageTokens = clientData->getServerToClientSendQueue().front().mMessageTokens;
                    for (size_t tokenIdx = 0; tokenIdx < messageTokens.size(); tokenIdx++)
                    {
                        sendMsg += messageTokens[tokenIdx];
                        if (tokenIdx != messageTokens.size() - 1)
                            sendMsg += " ";
                    }

                    if (clientData->getClientNickname().empty())
                        Logger::log(SEND, clientData->getIp() + " : " + sendMsg);
                    else
                        Logger::log(SEND, clientData->getClientNickname() + " : " + sendMsg);
                    sendMsg += "\r\n";

                    // Pop message from queue
                    clientData->getServerToClientSendQueue().pop();
                    
                    // Set sending buffer by sendMsg
                    clientData->setSendBuffer(sendMsg);
                }          

                // Send to client
                std::string buffToSend = clientData->getSendBuffer();
                const int sendMsgLength = send(clientFD, buffToSend.c_str(), buffToSend.length(), 0);
                if (SOCKET_ERROR == sendMsgLength)
                {
                    Logger::log(ERROR, "Failed to send message to client");
                    Server::disconnectClientDataFromServer(clientData);
                    Logger::log(ERROR, "Client disconnected");
                    continue;
                }

                // Maybe kernel buffer or client receive buffer is full
                else if (sendMsgLength == 0)
                {
                   continue; 
                }

                // Remove the part of sent
                buffToSend.erase(0, sendMsgLength);
                clientData->setSendBuffer(buffToSend);

                // Disable EVFILT_WRITE filter when the message is fully sent
                if (buffToSend.empty() && clientData->getServerToClientSendQueue().empty())
                {
                    struct kevent newSendEvent;
                    memset(&newSendEvent, 0, sizeof(newSendEvent));
                    newSendEvent.ident = clientFD;
                    newSendEvent.filter = EVFILT_WRITE;
                    newSendEvent.flags = EV_DELETE;
                    newSendEvent.data = 0;
                    newSendEvent.udata = NULL;
                    if (kevent(mhKqueue, &newSendEvent, 1, NULL, 0, NULL) == -1)
                    {
                        Logger::log(ERROR, "Failed to disable EVFILT_WRITE event");
                        std::perror("kevent");
                        close(clientFD);
                        assert(false);
                        continue;
                    }
                    continue;
                }
            }
        }

        // Pass messages to MessageHandler after handling all events
        {
            // TODO : push messages to clients
            // we must check message's validity, hence we need to parse it, and store it in the clientData object
            {
                SOCKET_FD clientFD = -1;
                // send receivedRequest to clientData, and server will handle the message
                if (!mRecvedStrPerClientDataProcessQueue.empty())
                {
                    clientFD = mRecvedStrPerClientDataProcessQueue.front();
                    mRecvedStrPerClientDataProcessQueue.pop();
                    Logger::log(DEBUG, "Parsing received message to clientData object");
                }
                // check every clientData object in the map once, if there is message to parse
                else
                {
                    std::map<SOCKET_FD, ClientData*>::const_iterator clientDataIter = mFdToClientGlobalMap.begin();
                    while (clientDataIter != mFdToClientGlobalMap.end())
                    {
                        clientFD = clientDataIter->first;
                        ClientData* clientData = clientDataIter->second;
                        if (parseReceivedRequestFromClientData(clientData) == true)
                        {
                            Logger::log(DEBUG, "Message parsed successfully");
                            Logger::log(DEBUG, "Added to executeMessageQueue");
                            // This logic Takes O(log N), probably can optimize it

                            clientDataIter = mFdToClientGlobalMap.find(clientFD);
                            // clientData = mFdToClientGlobalMap.find(clientFD)->second;
                            if (clientDataIter == mFdToClientGlobalMap.end())
                            {
                                // QUIT or disconnected already.
                                Logger::log(WARNING, "Got Parsed Message from Client, but ClientData not found");
                                Logger::log(WARNING, "Probably client disconnected");
                                continue;
                            }
                            Logger::log(DEBUG, "There is " + ValToString(clientData->getExecuteMessageQueue().size()) + " messages in executeMessageQueue");
                            executeParsedMessages(clientData);
                        }
                        clientDataIter++;
                    }
                }

                std::map<SOCKET_FD, ClientData*>::const_iterator clientDataIter = mFdToClientGlobalMap.find(clientFD);
                if (clientDataIter == mFdToClientGlobalMap.end())
                {
                    // Logger::log(WARNING, "ClientData not found");
                    continue;
                }

                ClientData* clientData = clientDataIter->second;

                // add string to right clientData's receivedString

                while (parseReceivedRequestFromClientData(clientData) == true)
                {
                    Logger::log(DEBUG, "Message parsed successfully");
                    Logger::log(DEBUG, "Added to executeMessageQueue");
                    // This logic Takes O(log N), probably can optimize it

                    clientDataIter = mFdToClientGlobalMap.find(clientFD);
                    // clientData = mFdToClientGlobalMap.find(clientFD)->second;
                    if (clientDataIter == mFdToClientGlobalMap.end())
                    {
                        // QUIT or disconnected already.
                        Logger::log(WARNING, "Got Parsed Message from Client, but ClientData not found");
                        Logger::log(WARNING, "Probably client disconnected");
                        continue;
                    }
                    Logger::log(DEBUG, "There is " + ValToString(clientData->getExecuteMessageQueue().size()) + " messages in executeMessageQueue");
                    executeParsedMessages(clientData);
                }


                // executeParsedMessages(clientData);


                // QUIT or disconnected already.
                if (mFdToClientGlobalMap.find(clientFD) == mFdToClientGlobalMap.end())
                    continue;

                // Enable EVFILT_WRITE filter when there is message to send
                struct kevent newSendEvent;
                memset(&newSendEvent, 0, sizeof(newSendEvent));
                newSendEvent.ident = clientFD;
                newSendEvent.filter = EVFILT_WRITE;
                newSendEvent.flags = EV_ADD;
                newSendEvent.data = 0;
                newSendEvent.udata = NULL;
                if (kevent(mhKqueue, &newSendEvent, 1, NULL, 0, NULL) == -1)
                {
                    Logger::log(ERROR, "Failed to enable EVFILT_WRITE event, probably client disconnected");
                    close(clientFD);
                    continue;
                }
            }
        }
    }
}

void Server::executeParsedMessages(ClientData* clientData)
{
    // SOCKET_FD clientFD = clientData->getClientSocket();
    std::map<std::string, ClientData*>::const_iterator nickIter;
    while (clientData != NULL && !clientData->getExecuteMessageQueue().empty())
    {
        Message messageToExecute = clientData->getExecuteMessageQueue().front();
        clientData->getExecuteMessageQueue().pop();
        size_t commandStartPos = 0;
        size_t paramStartPos = 1;

        // Ignore prefix
        if (messageToExecute.mHasPrefix) // TODO : fix with this position
        {
            commandStartPos++;
            paramStartPos++;
        }

        // TODO: move these to somewhere below
        Message errMessageToClient;
        Message successMessageToClient;
        std::vector <std::string> channelNames;
        std::vector <std::string> channelKeys;

        size_t posStart;
        size_t posEnd;
        // Excute corresponding command
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
            if (mServerPassword == "" || (mServerPassword.length() == messageToExecute.mMessageTokens[commandStartPos + 1].length() && mServerPassword == messageToExecute.mMessageTokens[commandStartPos + 1]))
            {
                Logger::log(INFO, "Client Successfully sent PASS command and authenticated");

                successMessageToClient.mCommand = NOTICE;
                successMessageToClient.mMessageTokens.clear();
                successMessageToClient.mMessageTokens.push_back("NOTICE");
                successMessageToClient.mMessageTokens.push_back("AUTH");
                successMessageToClient.mMessageTokens.push_back(":*** Looking up your hostname...");

                clientData->getServerToClientSendQueue().push(successMessageToClient);
                clientData->setIsPassed(true);

                break;
            }
            else
            {
                Logger::log(WARNING, "Invalid password, disconnecting client");

                // We Cannot Send The Message To Client.

                // Server::logMessage(messageToExecute);
                // Message errMessageToClient;
                // errMessageToClient.mMessageTokens.push_back(ERR_PASSWDMISMATCH);
                // errMessageToClient.mMessageTokens.push_back(":*** Password Missmatched, disconnecting...");
                // clientData->getServerToClientSendQueue().push(errMessageToClient);

                Server::disconnectClientDataFromServer(clientData);
                Logger::log(DEBUG, "Client disconnected");

                break;
            }

        case NICK:

            //  If the server recieves an identical NICK from a client which is
            //  directly connected, it may issue an ERR_NICKCOLLISION to the local
            //  client, drop the NICK command, and not generate any kills.
            Logger::log(DEBUG, "executing NICK command from " + getIpFromClientData(clientData) + " with nickname " + messageToExecute.mMessageTokens[0]);
            if (clientData->getIsPassed() == false)
            {
                Logger::log(WARNING, "Client " + clientData->getClientNickname() + " is not passed");

                Server::logMessage(messageToExecute);
                Message errMessageToClient;
                errMessageToClient.mMessageTokens.push_back(ERR_NOTREGISTERED);
                errMessageToClient.mMessageTokens.push_back(":*** You have not registered");
                clientData->getServerToClientSendQueue().push(errMessageToClient);

                break;
            }
            nickIter = mNickToClientGlobalMap.find(messageToExecute.mMessageTokens[paramStartPos]);
            if (nickIter != mNickToClientGlobalMap.end())
            {
                Logger::log(WARNING, "Client " + clientData->getIp() + " tried to set nickname to " + messageToExecute.mMessageTokens[0] + " but it's already taken");

                Server::logMessage(messageToExecute);
                Message errMessageToClient;
                errMessageToClient.mMessageTokens.push_back(ERR_NICKNAMEINUSE);
                errMessageToClient.mMessageTokens.push_back(":*** Nickname is already in use");
                clientData->getServerToClientSendQueue().push(errMessageToClient);

                break;
            }

            successMessageToClient.mCommand = NOTICE;
            successMessageToClient.mMessageTokens.clear();
            successMessageToClient.mMessageTokens.push_back("NOTICE");
            successMessageToClient.mMessageTokens.push_back("AUTH");
            successMessageToClient.mMessageTokens.push_back(":*** Nickname accepted");
            clientData->getServerToClientSendQueue().push(successMessageToClient);

            clientData->setClientNickname(messageToExecute.mMessageTokens[paramStartPos]);

            // 닉변
            if (clientData->getIsNickSet() == true)
            {
                Message nickMessageToChannels;
                nickMessageToChannels.mCommand = NICK;
                nickMessageToChannels.mHasPrefix = true;
                nickMessageToChannels.mMessageTokens.push_back(":" + clientData->getClientNickname());
                nickMessageToChannels.mMessageTokens.push_back("NICK");
                nickMessageToChannels.mMessageTokens.push_back(messageToExecute.mMessageTokens[paramStartPos]);
                std::map<std::string, Channel*> connectedChannels = clientData->getConnectedChannels();
                for (std::map<std::string, Channel*>::iterator channelIter = connectedChannels.begin(); channelIter != connectedChannels.end(); channelIter++)
                {
                    Server::sendMessagetoChannel(channelIter->second, nickMessageToChannels);
                }
            }

            mNickToClientGlobalMap[messageToExecute.mMessageTokens[paramStartPos]] = clientData;
            Logger::log(INFO, "Client " + clientData->getClientNickname() + " set nickname to " + messageToExecute.mMessageTokens[0]);

            clientData->setIsNickSet(true);

            if (clientData->getIsNickSet() == true && clientData->getIsUserSet() == true)
            {
                if (clientData->getIsReadyToChat() == false)
                    Server::sendWelcomeMessageToClientData(clientData);
                clientData->setIsReadyToChat(true);
            }

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
            if (clientData->getIsPassed() == false)
            {
                Logger::log(WARNING, "Client " + clientData->getClientNickname() + " is not passed");

                Server::logMessage(messageToExecute);
                Message errMessageToClient;
                errMessageToClient.mMessageTokens.push_back(ERR_NOTREGISTERED);
                errMessageToClient.mMessageTokens.push_back(":*** You have not registered");
                clientData->getServerToClientSendQueue().push(errMessageToClient);

                break;
            }

            successMessageToClient.mCommand = NOTICE;
            successMessageToClient.mMessageTokens.push_back("NOTICE");
            successMessageToClient.mMessageTokens.push_back("AUTH");
            successMessageToClient.mMessageTokens.push_back(":*** Checking Ident");

            clientData->getServerToClientSendQueue().push(successMessageToClient);
            successMessageToClient.mMessageTokens.clear();
            successMessageToClient.mMessageTokens.push_back("NOTICE");
            successMessageToClient.mMessageTokens.push_back("AUTH");
            successMessageToClient.mMessageTokens.push_back(":*** Actually we don't check ident");
            clientData->getServerToClientSendQueue().push(successMessageToClient);

            successMessageToClient.mMessageTokens.clear();
            successMessageToClient.mMessageTokens.push_back("NOTICE");
            successMessageToClient.mMessageTokens.push_back("AUTH");
            successMessageToClient.mMessageTokens.push_back(":*** cuz we don't communicate with other servers lol");
            clientData->getServerToClientSendQueue().push(successMessageToClient);

            clientData->setUsername(messageToExecute.mMessageTokens[paramStartPos]);
            clientData->setHostname(messageToExecute.mMessageTokens[paramStartPos + 1]);
            clientData->setServername(messageToExecute.mMessageTokens[paramStartPos + 2]);
            clientData->setRealname(messageToExecute.mMessageTokens[paramStartPos + 3]);

            Logger::log(INFO, "Client " + clientData->getClientNickname() + " set username to " + messageToExecute.mMessageTokens[paramStartPos]);
            Logger::log(INFO, "Client " + clientData->getClientNickname() + " set hostname to " + messageToExecute.mMessageTokens[paramStartPos + 1]);
            Logger::log(INFO, "Client " + clientData->getClientNickname() + " set servername to " + messageToExecute.mMessageTokens[paramStartPos + 2]);
            Logger::log(INFO, "Client " + clientData->getClientNickname() + " set realname to " + messageToExecute.mMessageTokens[paramStartPos + 3]);

            clientData->setIsUserSet(true);

            if (clientData->getIsNickSet() == true && clientData->getIsPassed() == true && clientData->getIsUserSet() == true)
            {
                clientData->setIsReadyToChat(true);

                Server::sendWelcomeMessageToClientData(clientData);
            }

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

            if (clientData->getIsReadyToChat() == false)
            {
                Logger::log(ERROR, "Client is not ready to chat, sending ERR_NOTREGISTERED");
                errMessageToClient.mMessageTokens.push_back(ERR_NOTREGISTERED);
                errMessageToClient.mMessageTokens.push_back(":You have not registered yet");
                clientData->getServerToClientSendQueue().push(errMessageToClient);
                Server::logClientData(clientData);
                break;
            }

            // channels and keys are separated by ','
            // add channel to channelNames vector
            Logger::log(DEBUG, "Parsing channel names and keys");
            posStart = 0;
            posEnd = messageToExecute.mMessageTokens[paramStartPos].find(',');
            while (posEnd != std::string::npos)
            {
                std::string channelName = messageToExecute.mMessageTokens[paramStartPos].substr(posStart, posEnd);
                if (channelName.length() == 0)
                {
                    Logger::log(ERROR, "Channel name is empty, sending ERR_NEEDMOREPARAMS");
                    errMessageToClient.mMessageTokens.push_back(ERR_NEEDMOREPARAMS);
                    errMessageToClient.mMessageTokens.push_back(":Channel name is empty");
                    clientData->getServerToClientSendQueue().push(errMessageToClient);
                    Server::logClientData(clientData);
                    return;
                }
                else if (channelName.length() > MAX_CHANNEL_NAME_LENGTH)
                {
                    Logger::log(ERROR, "Channel name is too long, sending ERR_NOSUCHCHANNEL");
                    errMessageToClient.mMessageTokens.push_back(ERR_NOSUCHCHANNEL);
                    errMessageToClient.mMessageTokens.push_back(":Channel name is too long");
                    clientData->getServerToClientSendQueue().push(errMessageToClient);
                    Server::logClientData(clientData);
                    return;
                }
                else if (channelName[0] != '#' && channelName[0] != '&')
                {
                    Logger::log(ERROR, "Channel name is invalid, sending ERR_NOSUCHCHANNEL");
                    errMessageToClient.mMessageTokens.push_back(ERR_NOSUCHCHANNEL);
                    errMessageToClient.mMessageTokens.push_back(":Channel name is invalid");
                    clientData->getServerToClientSendQueue().push(errMessageToClient);
                    Server::logClientData(clientData);
                    return;
                }
                channelNames.push_back(channelName);
                messageToExecute.mMessageTokens[paramStartPos].erase(posStart, posEnd + 1); 
                posStart = 0;
                posEnd = messageToExecute.mMessageTokens[paramStartPos].find(',', posStart);
            }
            // add last channel to channelNames vector
            {
                std::string channelName = messageToExecute.mMessageTokens[paramStartPos].substr(posStart, posEnd);
                if (channelName.length() == 0)
                {
                    Logger::log(ERROR, "Channel name is empty, sending ERR_NEEDMOREPARAMS");
                    errMessageToClient.mMessageTokens.push_back(ERR_NEEDMOREPARAMS);
                    errMessageToClient.mMessageTokens.push_back(":Channel name is empty");
                    clientData->getServerToClientSendQueue().push(errMessageToClient);
                    Server::logClientData(clientData);
                    return;
                }
                else if (channelName.length() > MAX_CHANNEL_NAME_LENGTH)
                {
                    Logger::log(ERROR, "Channel name is too long, sending ERR_NOSUCHCHANNEL");
                    errMessageToClient.mMessageTokens.push_back(ERR_NOSUCHCHANNEL);
                    errMessageToClient.mMessageTokens.push_back(":Channel name is too long");
                    clientData->getServerToClientSendQueue().push(errMessageToClient);
                    Server::logClientData(clientData);
                    return;
                }
                else if (channelName[0] != '#' && channelName[0] != '&')
                {
                    Logger::log(ERROR, "Channel name is invalid, sending ERR_NOSUCHCHANNEL");
                    errMessageToClient.mMessageTokens.push_back(ERR_NOSUCHCHANNEL);
                    errMessageToClient.mMessageTokens.push_back(":Channel name is invalid");
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
                errMessageToClient.mMessageTokens.push_back(ERR_NEEDMOREPARAMS);
                errMessageToClient.mMessageTokens.push_back(":No channel names");
                clientData->getServerToClientSendQueue().push(errMessageToClient);
                Server::logClientData(clientData);
                return;
            }
            // if there is key parameter, add it to channelKeys Vector
            if (messageToExecute.mMessageTokens.size() == paramStartPos + 2)
            {
                Logger::log(DEBUG, "Parsing channel keys");
                posStart = 0;
                posEnd = messageToExecute.mMessageTokens[paramStartPos + 1].find(',');
                while (posEnd != std::string::npos)
                {
                    std::string channelKey = messageToExecute.mMessageTokens[paramStartPos + 1].substr(posStart, posEnd);
                    if (channelKey.length() == 0)
                    {
                        Logger::log(ERROR, "Channel key is empty, sending ERR_NEEDMOREPARAMS");
                        errMessageToClient.mMessageTokens.push_back(ERR_NEEDMOREPARAMS);
                        errMessageToClient.mMessageTokens.push_back(":Channel key is empty");
                        clientData->getServerToClientSendQueue().push(errMessageToClient);
                        Server::logClientData(clientData);
                        return;
                    }
                    else if (channelKey.length() > MAX_CHANNEL_KEY_LENGTH)
                    {
                        Logger::log(ERROR, "Channel key is too long, sending ERR_BADCHANNELKEY");
                        errMessageToClient.mMessageTokens.push_back(ERR_BADCHANNELKEY);
                        errMessageToClient.mMessageTokens.push_back(":Channel key is too long");
                        clientData->getServerToClientSendQueue().push(errMessageToClient);
                        Server::logClientData(clientData);
                        return;
                    }
                    channelKeys.push_back(channelKey);
                    posStart = posEnd + 1;
                    posEnd = messageToExecute.mMessageTokens[paramStartPos + 1].find(',', posStart);
                }
                std::string channelKey = messageToExecute.mMessageTokens[paramStartPos + 1].substr(posStart, posEnd);
                if (channelKey.length() == 0)
                {
                    Logger::log(ERROR, "Channel key is empty, sending ERR_NEEDMOREPARAMS");
                    errMessageToClient.mMessageTokens.push_back(ERR_NEEDMOREPARAMS);
                    errMessageToClient.mMessageTokens.push_back(":Channel key is empty");
                    clientData->getServerToClientSendQueue().push(errMessageToClient);
                    Server::logClientData(clientData);
                    return;
                }
                else if (channelKey.length() > MAX_CHANNEL_KEY_LENGTH)
                {
                    Logger::log(ERROR, "Channel key is too long, sending ERR_BADCHANNELKEY");
                    errMessageToClient.mMessageTokens.push_back(ERR_BADCHANNELKEY);
                    errMessageToClient.mMessageTokens.push_back(":Channel key is too long");
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


            Logger::log(DEBUG, "Adding client to channels");


            // 331    RPL_NOTOPIC
            //          "<channel> :No topic is set"
            // 332    RPL_TOPIC
            //          "<channel> :<topic>"

            //        - When sending a TOPIC message to determine the
            //          channel topic, one of two replies is sent.  If
            //          the topic is set, RPL_TOPIC is sent back else
            //          RPL_NOTOPIC.
            // 353    RPL_NAMREPLY
            //        "( "=" / "*" / "@" ) <channel>
            //         :[ "@" / "+" ] <nick> *( " " [ "@" / "+" ] <nick> )
            //        - "@" is used for secret channels, "*" for private
            //          channels, and "=" for others (public channels).

            // 366    RPL_ENDOFNAMES
            //        "<channel> :End of NAMES list"

            //       - To reply to a NAMES message, a reply pair consisting
            //         of RPL_NAMREPLY and RPL_ENDOFNAMES is sent by the
            //         server back to the client.  If there is no channel
            //         found as in the query, then only RPL_ENDOFNAMES is


            // TODO: Fix logic
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


                std::map<std::string, Channel*>::iterator channelIter = mNameToChannelGlobalMap.find(channelNames[i]);

               

                // 채널이 없을 때
                if (channelIter == mNameToChannelGlobalMap.end())
                {
                    Logger::log(DEBUG, "Channel not found, creating new channel");
                    Channel* newChannel = new Channel(channelNames[i]);
                    mNameToChannelGlobalMap.insert(std::pair<std::string, Channel*>(channelNames[i], newChannel));

                    // 클라이언트한테 보내는 첫빠따
                    Message joinMessageToClient;
                    joinMessageToClient.mCommand = JOIN;
                    joinMessageToClient.mHasPrefix = true;
                    joinMessageToClient.mMessageTokens.push_back(":" + clientData->getClientNickname() + "!" + clientData->getUsername() + "@" + clientData->getHostname());
                    joinMessageToClient.mMessageTokens.push_back("JOIN");
                    joinMessageToClient.mMessageTokens.push_back(newChannel->getName());
                    clientData->getServerToClientSendQueue().push(joinMessageToClient);

                    // 채널에 비밀번호가 있을 때
                    if (channelKeys.size() > i)
                    {
                        // 채널에 보내는 메시지
                        Message joinMessageToChannel;
                        joinMessageToChannel.mCommand = JOIN;
                        joinMessageToChannel.mHasPrefix = true;
                        joinMessageToChannel.mMessageTokens.push_back(":" + clientData->getClientNickname() + "!" + clientData->getUsername() + "@" + clientData->getHostname());
                        joinMessageToChannel.mMessageTokens.push_back("JOIN");
                        joinMessageToChannel.mMessageTokens.push_back(newChannel->getName());
                        Server::sendMessagetoChannel(newChannel, joinMessageToChannel);

                        // 채널 클라 상호 연결
                        newChannel->getNickToClientDataMap()[clientData->getClientNickname()] = clientData;
                        newChannel->getNickToOperatorClientsMap()[clientData->getClientNickname()] = clientData;
                        clientData->getConnectedChannels().insert(std::pair<std::string, Channel*>(newChannel->getName(), newChannel));

                        // 332 353 366 to client (topic, names, endofnames)
                        Server::sendChannelJoinSucessMessageToClientData(clientData, newChannel);

                        newChannel->setPassword(channelKeys[i]);

                        Logger::log(INFO, "Channel created with password");
                        Logger::log(INFO, clientData->getClientNickname() + " joined Channel " + newChannel->getName() + " with password");
                        Server::logClientData(clientData);
                        continue;
                    }
                    Message joinMessageToChannel;

                    joinMessageToChannel.mCommand = JOIN;
                    joinMessageToChannel.mHasPrefix = true;
                    joinMessageToChannel.mMessageTokens.push_back(":" + clientData->getClientNickname() + "!" + clientData->getUsername() + "@" + clientData->getHostname());
                    joinMessageToChannel.mMessageTokens.push_back("JOIN");
                    joinMessageToChannel.mMessageTokens.push_back(newChannel->getName());
                    Server::sendMessagetoChannel(newChannel, joinMessageToChannel);

                    newChannel->getNickToClientDataMap()[clientData->getClientNickname()] = clientData;
                    newChannel->getNickToOperatorClientsMap()[clientData->getClientNickname()] = clientData;
                    clientData->getConnectedChannels().insert(std::pair<std::string, Channel*>(newChannel->getName(), newChannel));

                    sendChannelJoinSucessMessageToClientData(clientData, newChannel);

                    Logger::log(INFO, "Channel created without password");
                    Logger::log(INFO, clientData->getClientNickname() + " joined Channel " + newChannel->getName() + " with password");
                    Server::logClientData(clientData);
                    continue;
                }
                else
                {
                    Channel* channel = channelIter->second;

                    // 클라이언트한테 보내는 첫빠따
                    Message joinMessageToClient;
                    joinMessageToClient.mCommand = JOIN;
                    joinMessageToClient.mHasPrefix = true;
                    joinMessageToClient.mMessageTokens.push_back(":" + clientData->getClientNickname() + "!" + clientData->getUsername() + "@" + clientData->getHostname());
                    joinMessageToClient.mMessageTokens.push_back("JOIN");
                    joinMessageToClient.mMessageTokens.push_back(channel->getName());
                    clientData->getServerToClientSendQueue().push(joinMessageToClient);
                                                
                    if (channel == NULL)
                    {
                        Logger::log(ERROR, "Channel not found, sending ERR_NOSUCHCHANNEL");
                        errMessageToClient.mMessageTokens.push_back(ERR_NOSUCHCHANNEL);
                        errMessageToClient.mMessageTokens.push_back(":Channel not found");
                        clientData->getServerToClientSendQueue().push(errMessageToClient);
                        continue;
                    }

                    if (channel->getIsInviteOnly() == true)
                    {
                        Logger::log(ERROR, "Channel is invite only, sending ERR_INVITEONLYCHAN");
                        errMessageToClient.mMessageTokens.push_back(ERR_INVITEONLYCHAN);
                        errMessageToClient.mMessageTokens.push_back(":Channel is invite only");
                        clientData->getServerToClientSendQueue().push(errMessageToClient);
                        return;
                    }

                    if (channel->getNickToClientDataMap().find(clientData->getClientNickname()) != channel->getNickToClientDataMap().end())
                    {
                        Logger::log(ERROR, "Client is already in the channel, sending ERR_ALREADYINCHANNEL");
                        errMessageToClient.mMessageTokens.push_back(ERR_ALREADYINCHANNEL);
                        errMessageToClient.mMessageTokens.push_back(":Client is already in the channel");
                        clientData->getServerToClientSendQueue().push(errMessageToClient);
                        return;
                    }

                    if (!channel->getPassword().empty())
                    {
                        if (channelKeys.size() > i && channelKeys[i] == channel->getPassword())
                        {
                            Message joinMessageToChannel;
                            joinMessageToChannel.mCommand = JOIN;
                            joinMessageToChannel.mHasPrefix = true;
                            joinMessageToChannel.mMessageTokens.push_back(":" + clientData->getClientNickname() + "!" + clientData->getUsername() + "@" + clientData->getHostname());
                            joinMessageToChannel.mMessageTokens.push_back("JOIN");
                            joinMessageToChannel.mMessageTokens.push_back(channel->getName());
                            Server::sendMessagetoChannel(channel, joinMessageToChannel);
                            sendChannelJoinSucessMessageToClientData(clientData, channel);

                            channel->getNickToClientDataMap()[clientData->getClientNickname()] = clientData;
                            clientData->getConnectedChannels().insert(std::pair<std::string, Channel*>(channel->getName(), channel));
                         
                            Logger::log(INFO, clientData->getClientNickname() + " joined Channel " + channel->getName() + " with password");
                            Server::logClientData(clientData);

                            // send JOIN message to all clients in the channel

                            continue;
                        }
                        else
                        {
                            Logger::log(WARNING, "Invalid password, sending ERR_BADCHANNELKEY");
                            errMessageToClient.mMessageTokens.push_back(ERR_BADCHANNELKEY);
                            errMessageToClient.mMessageTokens.push_back(":Invalid password");
                            clientData->getServerToClientSendQueue().push(errMessageToClient);
                            continue;
                        }
                    }
                    
                    Message joinMessageToChannel;
                    joinMessageToChannel.mCommand = JOIN;
                    joinMessageToChannel.mHasPrefix = true;
                    joinMessageToChannel.mMessageTokens.push_back(":" + clientData->getClientNickname() + "!" + clientData->getUsername() + "@" + clientData->getHostname());
                    joinMessageToChannel.mMessageTokens.push_back("JOIN");
                    joinMessageToChannel.mMessageTokens.push_back(channel->getName());
                    Server::sendMessagetoChannel(channel, joinMessageToChannel);
                    Server::sendChannelJoinSucessMessageToClientData(clientData, channel);

                    channel->getNickToClientDataMap()[clientData->getClientNickname()] = clientData;
                    clientData->getConnectedChannels().insert(std::pair<std::string, Channel*>(channel->getName(), channel));
   
                    Logger::log(INFO, clientData->getClientNickname() + "joined Channel " + channel->getName());
                    Server::logClientData(clientData);
                    // send JOIN message to all clients in the channel
               
                }
            }

            break;
        case PART:
{
            // ERR_NEEDMOREPARAMS              ERR_NOSUCHCHANNEL
            // ERR_NOTONCHANNEL

            // Examples:

            // PART #twilight_zone             ; leave channel "#twilight_zone"

            // PART #oz-ops,&group5            ; leave both channels "&group5" and
            //                                 "#oz-ops".

            // :WiZ PART #twilight_zone        ; leave channel "#twilight_zone"

            // parse channel names
            Logger::log(DEBUG, "executing PART command from");
            Server::logClientData(clientData);
            Server::logMessage(messageToExecute);
            if (clientData->getIsReadyToChat() == false)
            {
                Logger::log(ERROR, "Client is not ready to chat, sending ERR_NOTREGISTERED");
                errMessageToClient.mMessageTokens.push_back(ERR_NOTREGISTERED);
                errMessageToClient.mMessageTokens.push_back(":You have not registered yet");
                clientData->getServerToClientSendQueue().push(errMessageToClient);
                Server::logClientData(clientData);
                break;
            }

            // channels are separated by ','
            // add channel to channelNames vector
            Logger::log(DEBUG, "Parsing channel names");
            posStart = 0;
            posEnd = messageToExecute.mMessageTokens[paramStartPos].find(',');

            while (posEnd != std::string::npos)
            {
                std::string channelName = messageToExecute.mMessageTokens[paramStartPos].substr(posStart, posEnd);
                if (channelName.length() == 0)
                {
                    Logger::log(ERROR, "Channel name is empty, sending ERR_NEEDMOREPARAMS");
                    errMessageToClient.mMessageTokens.push_back(ERR_NEEDMOREPARAMS);
                    errMessageToClient.mMessageTokens.push_back(":Channel name is empty");
                    clientData->getServerToClientSendQueue().push(errMessageToClient);
                    Server::logClientData(clientData);
                    return;
                }
                else if (channelName[0] != '#' && channelName[0] != '&')
                {
                    Logger::log(ERROR, "Invalid channel name, sending ERR_NOSUCHCHANNEL");
                    errMessageToClient.mMessageTokens.push_back(ERR_NOSUCHCHANNEL);
                    errMessageToClient.mMessageTokens.push_back(":Invalid channel name");
                    clientData->getServerToClientSendQueue().push(errMessageToClient);
                    Server::logClientData(clientData);
                    return;
                }

                else if (channelName.length() > MAX_CHANNEL_NAME_LENGTH)
                {
                    Logger::log(ERROR, "Channel name is too long, sending ERR_NOSUCHCHANNEL");
                    errMessageToClient.mMessageTokens.push_back(ERR_NOSUCHCHANNEL);
                    errMessageToClient.mMessageTokens.push_back(":Channel name is too long");
                    clientData->getServerToClientSendQueue().push(errMessageToClient);
                    Server::logClientData(clientData);
                    return;
                }

                if (mNameToChannelGlobalMap.find(channelName) == mNameToChannelGlobalMap.end())
                {
                    Logger::log(ERROR, "Channel not found, sending ERR_NOSUCHCHANNEL");
                    errMessageToClient.mMessageTokens.push_back(ERR_NOSUCHCHANNEL);
                    errMessageToClient.mMessageTokens.push_back(":Channel not found");
                    clientData->getServerToClientSendQueue().push(errMessageToClient);
                    Server::logClientData(clientData);
                    return;
                }

                channelNames.push_back(channelName);
                posStart = posEnd + 1;
                posEnd = messageToExecute.mMessageTokens[paramStartPos].find(',', posStart);
            }
            // add last channel to channelNames vector
            {
                std::string channelName = messageToExecute.mMessageTokens[paramStartPos].substr(posStart, posEnd);
                if (channelName.length() == 0)
                {
                    Logger::log(ERROR, "Channel name is empty, sending ERR_NEEDMOREPARAMS");
                    errMessageToClient.mMessageTokens.push_back(ERR_NEEDMOREPARAMS);
                    errMessageToClient.mMessageTokens.push_back(":Channel name is empty");
                    clientData->getServerToClientSendQueue().push(errMessageToClient);
                    Server::logClientData(clientData);
                    return;
                }
                else if (channelName[0] != '#' && channelName[0] != '&')
                {
                    Logger::log(ERROR, "Invalid channel name, sending ERR_NOSUCHCHANNEL");
                    errMessageToClient.mMessageTokens.push_back(ERR_NOSUCHCHANNEL);
                    errMessageToClient.mMessageTokens.push_back(":Invalid channel name");
                    clientData->getServerToClientSendQueue().push(errMessageToClient);
                    Server::logClientData(clientData);
                    return;
                }
                else if (channelName.length() > MAX_CHANNEL_NAME_LENGTH)
                {
                    Logger::log(ERROR, "Channel name is too long, sending ERR_NOSUCHCHANNEL");
                    errMessageToClient.mMessageTokens.push_back(ERR_NOSUCHCHANNEL);
                    errMessageToClient.mMessageTokens.push_back(":Channel name is too long");
                    clientData->getServerToClientSendQueue().push(errMessageToClient);
                    Server::logClientData(clientData);
                    return;
                }

                if (mNameToChannelGlobalMap.find(channelName) == mNameToChannelGlobalMap.end())
                {
                    Logger::log(ERROR, "Channel not found, sending ERR_NOSUCHCHANNEL");
                    errMessageToClient.mMessageTokens.push_back(ERR_NOSUCHCHANNEL);
                    errMessageToClient.mMessageTokens.push_back(":Channel not found");
                    clientData->getServerToClientSendQueue().push(errMessageToClient);
                    Server::logClientData(clientData);
                    return;
                }

                channelNames.push_back(channelName);
            }

            std::string reason;
            // if last token starts with ':', it is a reason to leave
            if (messageToExecute.mMessageTokens.size() > paramStartPos + channelNames.size() && messageToExecute.mMessageTokens[paramStartPos + channelNames.size()][0] == ':')
            {
                reason = messageToExecute.mMessageTokens[paramStartPos + channelNames.size()].substr(1);
            }

            // remove channel from clientData
            for (size_t i = 0;i < channelNames.size(); i++)
            {
                std::map <std::string, Channel*>::iterator channelIter = mNameToChannelGlobalMap.find(channelNames[i]);

                Channel* channel = channelIter->second;

                clientData->getConnectedChannels().erase(channelNames[i]);

                // send PART message to channel
                Message clientPartMessage;
                clientPartMessage.mCommand = PART;
                clientPartMessage.mMessageTokens.clear();
                clientPartMessage.mHasPrefix = true;
                clientPartMessage.mMessageTokens.push_back(":" + clientData->getClientNickname()+"!"+clientData->getUsername()+"@"+clientData->getHostname());
                clientPartMessage.mMessageTokens.push_back("PART");
                clientPartMessage.mMessageTokens.push_back(channelNames[i]);
                if (!reason.empty())
                {
                    clientPartMessage.mMessageTokens.push_back(reason);
                }
                Server::sendMessagetoChannel(channel, clientPartMessage);
                channel->getNickToClientDataMap().erase(clientData->getClientNickname());
                channel->getNickToOperatorClientsMap().erase(clientData->getClientNickname());

                                // erase channel if no one is in it
                if (channel->getNickToClientDataMap().empty())
                {
                    delete channel;
                    mNameToChannelGlobalMap.erase(channelNames[i]);
                }
            }

            Logger::log(INFO, clientData->getClientNickname() + " left channels");
}
            break;
        case PRIVMSG:

            // ERR_NORECIPIENT                ERR_NOTEXTTOSEND
            // ERR_CANNOTSENDTOCHAN           ERR_NOTOPLEVEL
            // ERR_WILDTOPLEVEL               ERR_TOOMANYTARGETS
            // ERR_NOSUCHNICK                 ERR_NOSUCHSERVER

            // Examples:

            // :Angel PRIVMSG Wiz :Hello are you receiving this message ?
            //                                 ; Message from Angel to Wiz.
            if (clientData->getIsReadyToChat() == false)
            {
                Logger::log(ERROR, "Client is not ready to chat, sending ERR_NOTREGISTERED");
                errMessageToClient.mMessageTokens.push_back(ERR_NOTREGISTERED);
                errMessageToClient.mMessageTokens.push_back(":You have not registered yet");
                clientData->getServerToClientSendQueue().push(errMessageToClient);
                Server::logClientData(clientData);
                break;
            }

            Logger::log(DEBUG, "executing PRIVMSG command from");
            Server::logClientData(clientData);
            Server::logMessage(messageToExecute);

            // check if there is a recipient
            if (messageToExecute.mMessageTokens.size() < paramStartPos + 1)
            {
                Logger::log(ERROR, "No recipient, sending ERR_NORECIPIENT");
                errMessageToClient.mMessageTokens.push_back(ERR_NORECIPIENT);
                errMessageToClient.mMessageTokens.push_back(":No recipient");
                clientData->getServerToClientSendQueue().push(errMessageToClient);
                Server::logClientData(clientData);
                break;
            }

            // check if there is a text to send
            if (messageToExecute.mMessageTokens.size() < paramStartPos + 2)
            {
                Logger::log(ERROR, "No text to send, sending ERR_NOTEXTTOSEND");
                errMessageToClient.mMessageTokens.push_back(ERR_NOTEXTTOSEND);
                errMessageToClient.mMessageTokens.push_back(":No text to send");
                clientData->getServerToClientSendQueue().push(errMessageToClient);
                Server::logClientData(clientData);
                break;
            }

            // check if recipient is a channel

            {
                std::string recipient = messageToExecute.mMessageTokens[paramStartPos];
                std::string text = messageToExecute.mMessageTokens[paramStartPos + 1];

                if (recipient[0] == '#' || recipient[0] == '&')
                {
                    Logger::log(DEBUG, "Recipient is a channel");
                    std::map<std::string, Channel*>::iterator channelIter = mNameToChannelGlobalMap.find(recipient);
                    if (channelIter == mNameToChannelGlobalMap.end())
                    {
                        Logger::log(ERROR, "Channel not found, sending ERR_NOSUCHCHANNEL");
                        errMessageToClient.mMessageTokens.push_back(ERR_NOSUCHCHANNEL);
                        errMessageToClient.mMessageTokens.push_back(":Channel not found");
                        clientData->getServerToClientSendQueue().push(errMessageToClient);
                        Server::logClientData(clientData);
                        break;
                    }

                    Channel* channel = channelIter->second;
                    if (channel->getNickToClientDataMap().find(clientData->getClientNickname()) == channel->getNickToClientDataMap().end())
                    {
                        Logger::log(ERROR, "Client is not in the channel, sending ERR_CANNOTSENDTOCHAN");
                        errMessageToClient.mMessageTokens.push_back(ERR_CANNOTSENDTOCHAN);
                        errMessageToClient.mMessageTokens.push_back(":Client is not in the channel");
                        clientData->getServerToClientSendQueue().push(errMessageToClient);
                        Server::logClientData(clientData);
                        break;
                    }

                    // send message to channel
                    Message clientMessage;
                    clientMessage.mCommand = PRIVMSG;
                    clientMessage.mMessageTokens.clear();
                    clientMessage.mHasPrefix = true;
                    clientMessage.mMessageTokens.push_back(":" + clientData->getClientNickname());
                    clientMessage.mMessageTokens.push_back("PRIVMSG");
                    clientMessage.mMessageTokens.push_back(channel->getName());
                    clientMessage.mMessageTokens.push_back(text);
                    Server::sendMessagetoChannel(channel, clientMessage);
                }
                else
                {
                    Logger::log(DEBUG, "Recipient is a user");
                    std::map<std::string, ClientData*>::iterator clientIter = mNickToClientGlobalMap.find(recipient);
                    if (clientIter == mNickToClientGlobalMap.end())
                    {
                        Logger::log(ERROR, "Client not found, sending ERR_NOSUCHNICK");
                        errMessageToClient.mMessageTokens.push_back(ERR_NOSUCHNICK);
                        errMessageToClient.mMessageTokens.push_back(":Client not found");
                        clientData->getServerToClientSendQueue().push(errMessageToClient);
                        Server::logClientData(clientData);
                        break;
                    }

                    ClientData* recipientClientData = clientIter->second;

                    // send message to recipient
                    Message clientMessage;
                    clientMessage.mCommand = PRIVMSG;
                    clientMessage.mMessageTokens.clear();
                    clientMessage.mHasPrefix = true;
                    clientMessage.mMessageTokens.push_back(":" + clientData->getClientNickname());
                    clientMessage.mMessageTokens.push_back("PRIVMSG");
                    clientMessage.mMessageTokens.push_back(recipient);
                    clientMessage.mMessageTokens.push_back(text);
                    recipientClientData->getServerToClientSendQueue().push(clientMessage);
                }
            }
            break;

        case QUIT:
            // disconnect client
        {
            Logger::log(DEBUG, "executing QUIT command from");
            Server::logClientData(clientData);

            // TODO: delete things and close socket
            Logger::log(DEBUG, "getting connected channels");
            std::map <std::string, Channel*> connectedChannels = clientData->getConnectedChannels();
            Logger::log(DEBUG, "iterating through connected channels");
            for (std::map<std::string, Channel*>::iterator it = connectedChannels.begin(); it != connectedChannels.end(); it++)
            {
                Message quitMessage;
                quitMessage.mCommand = QUIT;
                quitMessage.mMessageTokens.clear();
                quitMessage.mHasPrefix = true;
                quitMessage.mMessageTokens.push_back(":" + clientData->getClientNickname() + "!" + clientData->getUsername() + "@" + clientData->getHostname());
                quitMessage.mMessageTokens.push_back("QUIT");
                if (messageToExecute.mMessageTokens.size() > paramStartPos)
                {
                    quitMessage.mMessageTokens.push_back(messageToExecute.mMessageTokens[paramStartPos]);
                }
                else
                {
                    quitMessage.mMessageTokens.push_back("Client quit");
                }
                Server::sendMessagetoChannel(it->second, quitMessage);
                Server::disconnectClientDataWithChannel(clientData, it->second);
            }

            Server::disconnectClientDataFromServer(clientData);
        }

        // THIS IS THE LAST MESSAGE OF CLIENT!
        // WE MUST RETURN NOW!
        return;

        case KICK:

            //             Command: KICK
            //    Parameters: <channel> <user> [<comment>]

            //    The KICK command can be  used  to  forcibly  remove  a  user  from  a
            //    channel.   It  'kicks  them  out'  of the channel (forced PART).

            //    Only a channel operator may kick another user out of a  channel.
            //    Each  server that  receives  a KICK message checks that it is valid
            //    (ie the sender is actually a  channel  operator)  before  removing
            //    the  victim  from  the channel.

            //    Numeric Replies:

            //            ERR_NEEDMOREPARAMS              ERR_NOSUCHCHANNEL
            //            ERR_BADCHANMASK                 ERR_CHANOPRIVSNEEDED
            //            ERR_NOTONCHANNEL

            //    Examples:

            // KICK &Melbourne Matthew         ; Kick Matthew from &Melbourne

            // KICK #Finnish John :Speaking English
            //                                 ; Kick John from #Finnish using
            //                                 "Speaking English" as the reason
            //                                 (comment).

            // :WiZ KICK #Finnish John         ; KICK message from WiZ to remove John
            //                                 from channel #Finnish

            // NOTE:
            //      It is possible to extend the KICK command parameters to the
            // following:

            // <channel>{,<channel>} <user>{,<user>} [<comment>]

            //    This extension to the KICK command is only available to operators.

            // parse channel names
            if (clientData->getIsReadyToChat() == false)
            {
                Logger::log(ERROR, "Client is not ready to chat, sending ERR_NOTREGISTERED");
                errMessageToClient.mMessageTokens.push_back(ERR_NOTREGISTERED);
                errMessageToClient.mMessageTokens.push_back(":You have not registered yet");
                clientData->getServerToClientSendQueue().push(errMessageToClient);
                Server::logClientData(clientData);
                break;
            }
            Logger::log(DEBUG, "executing KICK command from");
            Server::logClientData(clientData);
            Server::logMessage(messageToExecute);

            Logger::log(DEBUG, "Parsing channel names");

            // only one channel
            {
                std::string channelName = messageToExecute.mMessageTokens[paramStartPos];
                if (channelName.length() == 0)
                {
                    Logger::log(ERROR, "Channel name is empty, sending ERR_NEEDMOREPARAMS");
                    errMessageToClient.mMessageTokens.push_back(ERR_NEEDMOREPARAMS);
                    errMessageToClient.mMessageTokens.push_back(":Channel name is empty");
                    clientData->getServerToClientSendQueue().push(errMessageToClient);
                    Server::logClientData(clientData);
                    return;

                }
                else if (channelName[0] != '#' && channelName[0] != '&')
                {
                    Logger::log(ERROR, "Invalid channel name, sending ERR_NOSUCHCHANNEL");
                    errMessageToClient.mMessageTokens.push_back(ERR_NOSUCHCHANNEL);
                    errMessageToClient.mMessageTokens.push_back(":Invalid channel name");
                    clientData->getServerToClientSendQueue().push(errMessageToClient);
                    Server::logClientData(clientData);
                    return;
                }
                else if (channelName.length() > MAX_CHANNEL_NAME_LENGTH)
                {
                    Logger::log(ERROR, "Channel name is too long, sending ERR_NOSUCHCHANNEL");
                    errMessageToClient.mMessageTokens.push_back(ERR_NOSUCHCHANNEL);
                    errMessageToClient.mMessageTokens.push_back(":Channel name is too long");
                    clientData->getServerToClientSendQueue().push(errMessageToClient);
                    Server::logClientData(clientData);
                    return;
                }

                std::map <std::string, Channel*>::iterator channelIter = mNameToChannelGlobalMap.find(channelName);

                if (channelIter == mNameToChannelGlobalMap.end())
                {
                    Logger::log(ERROR, "Channel not found, sending ERR_NOSUCHCHANNEL");
                    errMessageToClient.mMessageTokens.push_back(ERR_NOSUCHCHANNEL);
                    errMessageToClient.mMessageTokens.push_back(":Channel not found");
                    clientData->getServerToClientSendQueue().push(errMessageToClient);
                    Server::logClientData(clientData);
                    return;
                }

                // is user operator
                Channel* channel = channelIter->second;
                if (channel->getNickToOperatorClientsMap().find(clientData->getClientNickname()) == channel->getNickToOperatorClientsMap().end())
                {
                    Logger::log(ERROR, "Client is not operator, sending ERR_CHANOPRIVSNEEDED");
                    errMessageToClient.mMessageTokens.push_back(ERR_CHANOPRIVSNEEDED);
                    errMessageToClient.mMessageTokens.push_back(":Client is not operator");
                    clientData->getServerToClientSendQueue().push(errMessageToClient);
                    Server::logClientData(clientData);
                    return;
                }

                // param start pos + 1 is the user to kick
                std::string userToKick = messageToExecute.mMessageTokens[paramStartPos + 1];
                if (userToKick.length() == 0)
                {
                    Logger::log(ERROR, "User to kick is empty, sending ERR_NEEDMOREPARAMS");
                    errMessageToClient.mMessageTokens.push_back(ERR_NEEDMOREPARAMS);
                    errMessageToClient.mMessageTokens.push_back("User to kick is empty");
                    clientData->getServerToClientSendQueue().push(errMessageToClient);
                    Server::logClientData(clientData);
                    return;
                }
                else if (userToKick.length() > MAX_NICKNAME_LENGTH)
                {
                    Logger::log(ERROR, "User to kick is too long, sending ERR_NOSUCHNICK");
                    errMessageToClient.mMessageTokens.push_back(ERR_NOSUCHNICK);
                    errMessageToClient.mMessageTokens.push_back(":User to kick is too long");
                    clientData->getServerToClientSendQueue().push(errMessageToClient);
                    Server::logClientData(clientData);
                    return;
                }

                if (channel->getNickToClientDataMap().find(userToKick) == channel->getNickToClientDataMap().end())
                {
                    Logger::log(ERROR, "User not found in the channel, sending ERR_NOSUCHNICK");
                    errMessageToClient.mMessageTokens.push_back(ERR_NOSUCHNICK);
                    errMessageToClient.mMessageTokens.push_back(":User not found in the channel");
                    clientData->getServerToClientSendQueue().push(errMessageToClient);
                    Server::logClientData(clientData);
                    return;
                }

                ClientData* clientToKick = channel->getNickToClientDataMap().find(userToKick)->second;
                
                // remove user from channel
                successMessageToClient.mCommand = NONE;
                successMessageToClient.mMessageTokens.clear();
                successMessageToClient.mHasPrefix = true;
                successMessageToClient.mMessageTokens.push_back(":" + clientData->getClientNickname() + "!" + clientData->getUsername() + "@" + clientData->getHostname());
                successMessageToClient.mMessageTokens.push_back("KICK");
                successMessageToClient.mMessageTokens.push_back(channelName);
                successMessageToClient.mMessageTokens.push_back(userToKick);
                successMessageToClient.mMessageTokens.push_back(":Kicked from channel");
                Server::sendMessagetoChannel(channel, successMessageToClient);

                channel->getNickToClientDataMap().erase(userToKick);
                if (channel->getNickToClientDataMap().empty())
                {
                    mNameToChannelGlobalMap.erase(channelName);
                }
                clientToKick->getConnectedChannels().erase(channelName);
            }
            break;

        case INVITE:
            // ERR_NEEDMOREPARAMS              ERR_NOSUCHNICK
            // ERR_NOTONCHANNEL               ERR_USERONCHANNEL
            // ERR_CHANOPRIVSNEEDED

            // INVITE nick channel
            if (clientData->getIsReadyToChat() == false)
            {
                Logger::log(ERROR, "Client is not ready to chat, sending ERR_NOTREGISTERED");
                errMessageToClient.mMessageTokens.push_back(ERR_NOTREGISTERED);
                errMessageToClient.mMessageTokens.push_back(":You have not registered yet");
                clientData->getServerToClientSendQueue().push(errMessageToClient);
                Server::logClientData(clientData);
                break;
            }
            if (messageToExecute.mMessageTokens.size() < paramStartPos + 2)
            {
                Logger::log(ERROR, "Not enough parameters, sending ERR_NEEDMOREPARAMS");
                errMessageToClient.mMessageTokens.push_back(ERR_NEEDMOREPARAMS);
                errMessageToClient.mMessageTokens.push_back(":Not enough parameters");
                clientData->getServerToClientSendQueue().push(errMessageToClient);
                Server::logClientData(clientData);
                return;
            }

            {
                std::string channelName = messageToExecute.mMessageTokens[paramStartPos + 1];

                std::map <std::string, Channel*>::iterator channelIter = mNameToChannelGlobalMap.find(channelName);

                if (channelIter == mNameToChannelGlobalMap.end())
                {
                    Logger::log(ERROR, "Channel not found, sending ERR_NOSUCHCHANNEL");
                    errMessageToClient.mMessageTokens.push_back(ERR_NOSUCHCHANNEL);
                    errMessageToClient.mMessageTokens.push_back(":Channel not found");
                    clientData->getServerToClientSendQueue().push(errMessageToClient);
                    Server::logClientData(clientData);
                    return;
                }

                Channel* channel = channelIter->second;

                if (channel->getNickToClientDataMap().find(clientData->getClientNickname()) == channel->getNickToClientDataMap().end())
                {
                    Logger::log(ERROR, "Client is not in the channel, sending ERR_NOTONCHANNEL");
                    errMessageToClient.mMessageTokens.push_back(ERR_NOTONCHANNEL);
                    errMessageToClient.mMessageTokens.push_back(":Client is not in the channel");
                    clientData->getServerToClientSendQueue().push(errMessageToClient);
                    Server::logClientData(clientData);
                    return;
                }

                if (channel->getNickToClientDataMap().find(messageToExecute.mMessageTokens[paramStartPos]) != channel->getNickToClientDataMap().end())
                {
                    Logger::log(ERROR, "User is already in the channel, sending ERR_USERONCHANNEL");
                    errMessageToClient.mMessageTokens.push_back(ERR_USERONCHANNEL);
                    errMessageToClient.mMessageTokens.push_back(":User is already in the channel");
                    clientData->getServerToClientSendQueue().push(errMessageToClient);
                    Server::logClientData(clientData);
                    return;
                }

                if (channel->getNickToOperatorClientsMap().find(clientData->getClientNickname()) == channel->getNickToOperatorClientsMap().end())
                {
                    Logger::log(ERROR, "Client is not operator, sending ERR_CHANOPRIVSNEEDED");
                    errMessageToClient.mMessageTokens.push_back(ERR_CHANOPRIVSNEEDED);
                    errMessageToClient.mMessageTokens.push_back(":Client is not operator");
                    clientData->getServerToClientSendQueue().push(errMessageToClient);
                    Server::logClientData(clientData);
                    return;
                }

                std::map <std::string, ClientData*>::iterator invitedClientIter = mNickToClientGlobalMap.find(messageToExecute.mMessageTokens[paramStartPos]);
                if (invitedClientIter == mNickToClientGlobalMap.end())
                {
                    Logger::log(ERROR, "User not found, sending ERR_NOSUCHNICK");
                    errMessageToClient.mMessageTokens.push_back(ERR_NOSUCHNICK);
                    errMessageToClient.mMessageTokens.push_back(":User not found");
                    clientData->getServerToClientSendQueue().push(errMessageToClient);
                    Server::logClientData(clientData);
                    return;
                }

                ClientData* invitedClient = invitedClientIter->second;

                invitedClient->getServerToClientSendQueue().push(messageToExecute);

    
                // successMessageToClient.mCommand = NONE;
                // successMessageToClient.mMessageTokens.clear();
                // successMessageToClient.mHasPrefix = true;
                // successMessageToClient.mMessageTokens.push_back(clientData->getClientNickname() + "!" + clientData->getUsername() + "@" + clientData->getHostname());
                // successMessageToClient.mMessageTokens.push_back("INVITE");
                // successMessageToClient.mMessageTokens.push_back(channelName);
                // successMessageToClient.mMessageTokens.push_back(messageToExecute.mMessageTokens[paramStartPos + 1]);
                // successMessageToClient.mMessageTokens.push_back(":Invited to channel");
                // clientData->getServerToClientSendQueue().push(successMessageToClient);

            
                // Server::connectClientDataWithChannel(invitedClient, channel);
                // :euroserv.fr.quakenet.org 221 haelime +i
                // :haelime!~a@121.135.181.41 MODE haelime +i

                // :hae!~haeLoginN@121.135.181.35 INVITE haelime #haeChannel

                Message inviteMessageToInvitedClient;
                inviteMessageToInvitedClient.mCommand = NONE;
                inviteMessageToInvitedClient.mHasPrefix = true;
                inviteMessageToInvitedClient.mMessageTokens.push_back(":" + clientData->getClientNickname() + "!" + clientData->getUsername() + "@" + clientData->getHostname());
                inviteMessageToInvitedClient.mMessageTokens.push_back("INVITE");
                inviteMessageToInvitedClient.mMessageTokens.push_back(messageToExecute.mMessageTokens[paramStartPos]);
                inviteMessageToInvitedClient.mMessageTokens.push_back(channelName);
                inviteMessageToInvitedClient.mMessageTokens.push_back(":Invited to channel");
                invitedClient->getServerToClientSendQueue().push(inviteMessageToInvitedClient);

                // 채널 클라 상호 연결
                channel->getNickToClientDataMap()[invitedClient->getClientNickname()] = invitedClient;
                invitedClient->getConnectedChannels().insert(std::pair<std::string, Channel*>(channel->getName(), channel));

                // send JOIN message to all clients in the channel
                Message joinMessageToChannel;
                joinMessageToChannel.mCommand = JOIN;
                joinMessageToChannel.mHasPrefix = true;
                joinMessageToChannel.mMessageTokens.push_back(":" + invitedClient->getClientNickname() + "!" + invitedClient->getUsername() + "@" + invitedClient->getHostname());
                joinMessageToChannel.mMessageTokens.push_back("JOIN");
                joinMessageToChannel.mMessageTokens.push_back(channel->getName());
                Server::sendMessagetoChannel(channel, joinMessageToChannel);

                // Message nameReply = channel->getNameReply();
                // Message endOfNamesMessage = channel->getEndOfNames();
                
                // for (std::map<std::string, ClientData*>::iterator it = channel->getNickToClientDataMap().begin(); it != channel->getNickToClientDataMap().end(); it++)
                // {
                //     it->second->getServerToClientSendQueue().push(nameReply);
                //     invitedClient->getServerToClientSendQueue().push(endOfNamesMessage);
                // }

                

                // 332 353 366 to client (topic, names, endofnames)
                Server::sendChannelJoinSucessMessageToClientData(invitedClient, channel);

            }
            break;

        case TOPIC:

            // 3.2.4 Topic message

                // Command: TOPIC
                // Parameters: <channel> [ <topic> ]

                // The TOPIC command is used to change or view the topic of a channel.
                // The topic for channel <channel> is returned if there is no <topic>
                // given.  If the <topic> parameter is present, the topic for that
                // channel will be changed, if this action is allowed for the user
                // requesting it.  If the <topic> parameter is an empty string, the
                // topic for that channel will be removed.

                // Numeric Replies:

                //         ERR_NEEDMOREPARAMS              ERR_NOTONCHANNEL
                //         RPL_NOTOPIC                     RPL_TOPIC
                //         ERR_CHANOPRIVSNEEDED            ERR_NOCHANMODES

                // Examples:

                // :WiZ!jto@tolsun.oulu.fi TOPIC #test :New topic ; User Wiz setting the
                //                                 topic.

                // TOPIC #test :another topic      ; Command to set the topic on #test
                //                                 to "another topic".

                // TOPIC #test :                   ; Command to clear the topic on
                //                                 #test.

                // TOPIC #test                     ; Command to check the topic for
                //                                 #test.


            // SHOULD CHECK IF CHANNEL TOPIC NEEDS OPERATOR PRIVILEGES!!!!!!!!!!!!!!!!!!!

            if (clientData->getIsReadyToChat() == false)
            {
                Logger::log(ERROR, "Client is not ready to chat, sending ERR_NOTREGISTERED");
                errMessageToClient.mMessageTokens.push_back(ERR_NOTREGISTERED);
                errMessageToClient.mMessageTokens.push_back(":You have not registered yet");
                clientData->getServerToClientSendQueue().push(errMessageToClient);
                Server::logClientData(clientData);
                break;
            }
            if (messageToExecute.mHasPrefix)
            {
                commandStartPos++;
                paramStartPos++;
            }
            {
                std::map <std::string, Channel*>::iterator channelIter = mNameToChannelGlobalMap.find(messageToExecute.mMessageTokens[paramStartPos]);

                if (channelIter == mNameToChannelGlobalMap.end())
                {
                    Logger::log(ERROR, "Channel not found, sending ERR_NOTONCHANNEL");
                    errMessageToClient.mMessageTokens.push_back(ERR_NOTONCHANNEL);
                    errMessageToClient.mMessageTokens.push_back(":Channel not found");
                    clientData->getServerToClientSendQueue().push(errMessageToClient);
                    Server::logClientData(clientData);
                    return;
                }

                Channel* channel = channelIter->second;

                if (channel->getNickToClientDataMap().find(clientData->getClientNickname()) == channel->getNickToClientDataMap().end())
                {
                    Logger::log(ERROR, "Client is not in the channel, sending ERR_NOTONCHANNEL");
                    errMessageToClient.mMessageTokens.push_back(ERR_NOTONCHANNEL);
                    errMessageToClient.mMessageTokens.push_back(":Client is not in the channel");
                    clientData->getServerToClientSendQueue().push(errMessageToClient);
                    Server::logClientData(clientData);
                    return;
                }

                if (messageToExecute.mMessageTokens.size() == paramStartPos + 1)
                {
                    // return the topic
                    successMessageToClient.mCommand = TOPIC;
                    successMessageToClient.mMessageTokens.clear();
                    successMessageToClient.mHasPrefix = true;
                    successMessageToClient.mMessageTokens.push_back(":"+clientData->getClientNickname());
                    successMessageToClient.mMessageTokens.push_back(channel->getName());
                    successMessageToClient.mMessageTokens.push_back(channel->getTopic());
                    clientData->getServerToClientSendQueue().push(successMessageToClient);
                }
                else
                {
                    if (channel->getIsTopicRestricted() == true)
                    {
                        if (channel->getNickToOperatorClientsMap().find(clientData->getClientNickname()) == channel->getNickToOperatorClientsMap().end())
                        {
                            Logger::log(ERROR, "Client is not operator, sending ERR_CHANOPRIVSNEEDED");
                            errMessageToClient.mMessageTokens.push_back(ERR_CHANOPRIVSNEEDED);
                            errMessageToClient.mMessageTokens.push_back(":Client is not operator");
                            clientData->getServerToClientSendQueue().push(errMessageToClient);
                            Server::logClientData(clientData);
                            return;
                        }
                    }
                    // set the topic
                    channel->setTopic(messageToExecute.mMessageTokens[paramStartPos + 1]);
                    successMessageToClient.mCommand = TOPIC;
                    successMessageToClient.mMessageTokens.clear();
                    successMessageToClient.mHasPrefix = true;
                    successMessageToClient.mMessageTokens.push_back(":"+clientData->getClientNickname());
                    successMessageToClient.mMessageTokens.push_back("TOPIC");
                    successMessageToClient.mMessageTokens.push_back(channel->getName());
                    successMessageToClient.mMessageTokens.push_back(channel->getTopic());
                    Server::sendMessagetoChannel(channel, successMessageToClient);
                }
            }

            break;

            // NOT TESTED YET!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        case MODE:
            if (clientData->getIsReadyToChat() == false)
            {
                Logger::log(ERROR, "Client is not ready to chat, sending ERR_NOTREGISTERED");
                errMessageToClient.mMessageTokens.push_back(ERR_NOTREGISTERED);
                errMessageToClient.mMessageTokens.push_back(":You have not registered yet");
                clientData->getServerToClientSendQueue().push(errMessageToClient);
                Server::logClientData(clientData);
                break;
            }

            {//     Command: MODE
            // Parameters: <channel> *( ( "-" / "+" ) *<modes> *<modeparams> )
            // The MODE command is provided so that users may query and change the
            // characteristics of a channel.  For more details on available modes
            // and their uses, see "Internet Relay Chat: Channel Management" [IRC-
            // CHAN].  Note that there is a maximum limit of three (3) changes per
            // command for mode that take a parameter.

            // Numeric Replies:

            //         ERR_NEEDMOREPARAMS              ERR_KEYSET
            //         ERR_NOCHANMODES                 ERR_CHANOPRIVSNEEDED
            //         ERR_USERNOTINCHANNEL            ERR_UNKNOWNMODE
            //         RPL_CHANNELMODEIS
            //         RPL_BANLIST                     RPL_ENDOFBANLIST
            //         RPL_EXCEPTLIST                  RPL_ENDOFEXCEPTLIST
            //         RPL_INVITELIST                  RPL_ENDOFINVITELIST
            //         RPL_UNIQOPIS

            // The following examples are given to help understanding the syntax of
            // the MODE command, but refer to modes defined in "Internet Relay Chat:
            // Channel Management" [IRC-CHAN].

            // Examples:

            // MODE #Finnish +imI *!*@*.fi     ; Command to make #Finnish channel
            //                                 moderated and 'invite-only' with user
            //                                 with a hostname matching *.fi
            //                                 automatically invited.

            // MODE #Finnish +o Kilroy         ; Command to give 'chanop' privileges
            //                                 to Kilroy on channel #Finnish.

            // MODE #Finnish +v Wiz            ; Command to allow WiZ to speak on
            //                                 #Finnish.

            // MODE #Fins -s                   ; Command to remove 'secret' flag
            //                                 from channel #Fins.

            // MODE #42 +k oulu                ; Command to set the channel key to
            //                                 "oulu".

            // MODE #42 -k oulu                ; Command to remove the "oulu"
            //                                 channel key on channel "#42".

            // MODE #eu-opers +l 10            ; Command to set the limit for the
            //                                 number of users on channel
            //                                 "#eu-opers" to 10.

            // :WiZ!jto@tolsun.oulu.fi MODE #eu-opers -l
            //                                 ; User "WiZ" removing the limit for
            //                                 the number of users on channel "#eu-
            //                                 opers".

            // MODE &oulu +b                   ; Command to list ban masks set for
            //                                 the channel "&oulu".

            // MODE &oulu +b *!*@*             ; Command to prevent all users from
            //                                 joining.

            // MODE &oulu +b *!*@*.edu +e *!*@*.bu.edu
            //                                 ; Command to prevent any user from a
            //                                 hostname matching *.edu from joining,
            //                                 except if matching *.bu.edu

            // MODE #bu +be *!*@*.edu *!*@*.bu.edu
            //                                 ; Comment to prevent any user from a
            //                                 hostname matching *.edu from joining,
            //                                 except if matching *.bu.edu

            // MODE #meditation e              ; Command to list exception masks set
            //                                 for the channel "#meditation".

            // MODE #meditation I              ; Command to list invitations masks
            //                                 set for the channel "#meditation".

            // MODE !12345ircd O               ; Command to ask who the channel
            //                                 creator for "!12345ircd" is
            // i: Set/remove Invite-only channel
            // t: Set/remove the restrictions of the TOPIC command to channel operators
            // k: Set/remove the channel key (password)
            // o: Give/take channel operator privilege
            // l: Set/remove the user limit to channel


                std::map <std::string, Channel*>::iterator channelIter = mNameToChannelGlobalMap.find(messageToExecute.mMessageTokens[paramStartPos]);

                if (channelIter == mNameToChannelGlobalMap.end())
                {
                    Logger::log(ERROR, "Channel not found, sending ERR_NOTONCHANNEL");
                    errMessageToClient.mMessageTokens.push_back(ERR_NOTONCHANNEL);
                    errMessageToClient.mMessageTokens.push_back(":Channel not found");
                    clientData->getServerToClientSendQueue().push(errMessageToClient);
                    Server::logClientData(clientData);
                    return;
                }

                Channel* channel = channelIter->second;

                if (channel->getNickToClientDataMap().find(clientData->getClientNickname()) == channel->getNickToClientDataMap().end())
                {
                    Logger::log(ERROR, "Client is not in the channel, sending ERR_NOTONCHANNEL");
                    errMessageToClient.mMessageTokens.push_back(ERR_NOTONCHANNEL);
                    errMessageToClient.mMessageTokens.push_back(":Client is not in the channel");
                    clientData->getServerToClientSendQueue().push(errMessageToClient);
                    Server::logClientData(clientData);
                    return;
                }

                // check if the client is operator
                if (channel->getNickToOperatorClientsMap().find(clientData->getClientNickname()) == channel->getNickToOperatorClientsMap().end())
                {
                    Logger::log(ERROR, "Client is not operator, sending ERR_CHANOPRIVSNEEDED");
                    errMessageToClient.mMessageTokens.push_back(ERR_CHANOPRIVSNEEDED);
                    errMessageToClient.mMessageTokens.push_back(":Client is not operator");
                    clientData->getServerToClientSendQueue().push(errMessageToClient);
                    Server::logClientData(clientData);
                    return;
                }

                // parse modes
                std::string modeParams;
                if (messageToExecute.mMessageTokens.size() > paramStartPos + 1)
                     modeParams = messageToExecute.mMessageTokens[paramStartPos + 2];
                std::string mode = messageToExecute.mMessageTokens[paramStartPos + 1];

                if (mode.length() == 0)
                {
                    Logger::log(INFO, "No modes on this Channel");
                    successMessageToClient.mCommand = NONE;
                    successMessageToClient.mMessageTokens.clear();
                    successMessageToClient.mMessageTokens.push_back(RPL_CHANNELMODEIS);
                    successMessageToClient.mMessageTokens.push_back(channel->getName());
                    successMessageToClient.mMessageTokens.push_back(channel->getMode());
                    clientData->getServerToClientSendQueue().push(successMessageToClient);
                    Server::logClientData(clientData);
                    return;
                }
                if (mode.length() > 3)
                {
                    Logger::log(ERROR, "Too many modes, sending ERR_UNKNOWNMODE");
                    errMessageToClient.mMessageTokens.push_back(ERR_UNKNOWNMODE);
                    errMessageToClient.mMessageTokens.push_back(":Too many mode");
                    clientData->getServerToClientSendQueue().push(errMessageToClient);
                    Server::logClientData(clientData);
                    assert(false);
                    return;
                }
                if (mode[0] != '+' && mode[0] != '-')
                {
                    Logger::log(ERROR, "Invalid mode, sending ERR_UNKNOWNMODE");
                    errMessageToClient.mMessageTokens.push_back(ERR_UNKNOWNMODE);
                    errMessageToClient.mMessageTokens.push_back(":Invalid mode");
                    clientData->getServerToClientSendQueue().push(errMessageToClient);
                    Server::logClientData(clientData);
                    assert(false);
                    return;
                }
                // if ()

                // SET MODES
                for (size_t i = 0; i < mode.length(); i++)
                {
                    if (mode[i] == '+')
                    {
                        // set mode
                        switch (mode[i + 1])
                        {
                        case 'i':
                            channel->setInviteOnly(true);
                            break;
                        case 't':
                            channel->setTopicRestricted(true);
                            break;
                        case 'k':
                            if (mode.length() == 0)
                            {
                                Logger::log(ERROR, "Channel key is empty, sending ERR_KEYSET");
                                errMessageToClient.mMessageTokens.push_back(ERR_KEYSET);
                                errMessageToClient.mMessageTokens.push_back(":Channel key is empty");
                                clientData->getServerToClientSendQueue().push(errMessageToClient);
                                Server::logClientData(clientData);
                                assert(false);
                                return;
                            }
                            channel->setPassword(mode);
                            break;
                        case 'o':
                            // give operator privilege
                            if (channel->getNickToOperatorClientsMap().find(mode) == channel->getNickToOperatorClientsMap().end())
                            {
                                channel->getNickToOperatorClientsMap()[mode] = mNickToClientGlobalMap.find(mode)->second;
                            }
                            break;
                        case 'l':
                            if (mode.length() == 0)
                            {
                                Logger::log(ERROR, "User limit is empty, sending ERR_NEEDMOREPARAMS");
                                errMessageToClient.mMessageTokens.push_back(ERR_NEEDMOREPARAMS);
                                errMessageToClient.mMessageTokens.push_back(":User limit is empty");
                                clientData->getServerToClientSendQueue().push(errMessageToClient);
                                Server::logClientData(clientData);
                                assert(false);
                                return;
                            }
                            channel->setUserLimit(atoi(mode.c_str()));
                            break;
                        default:
                            Logger::log(ERROR, "Invalid mode, sending ERR_UNKNOWNMODE");
                            errMessageToClient.mMessageTokens.push_back(ERR_UNKNOWNMODE);
                            errMessageToClient.mMessageTokens.push_back(":Invalid mode");
                            clientData->getServerToClientSendQueue().push(errMessageToClient);
                            Server::logClientData(clientData);
                            // assert(false);
                            return;
                        }
                    }
                    else if (mode[i] == '-')
                    {
                        // remove mode
                        switch (mode[i + 1])
                        {
                        case 'i':
                            channel->setInviteOnly(false);
                            break;
                        case 't':
                            channel->setTopicRestricted(false);
                            break;
                        case 'k':
                            channel->clearPassword();
                            break;
                        case 'o':
                            // take operator privilege
                            if (channel->getNickToOperatorClientsMap().find(mode) != channel->getNickToOperatorClientsMap().end())
                            {
                                Logger::log(DEBUG, "Removing operator privilege");
                                channel->getNickToOperatorClientsMap().erase(mode);
                            }
                            break;
                        case 'l':
                            channel->setUserLimit(0);
                            break;
                        default:
                            Logger::log(ERROR, "Invalid mode, sending ERR_UNKNOWNMODE");
                            errMessageToClient.mMessageTokens.push_back(ERR_UNKNOWNMODE);
                            errMessageToClient.mMessageTokens.push_back(":Invalid mode");
                            clientData->getServerToClientSendQueue().push(errMessageToClient);
                            Server::logClientData(clientData);
                            assert(false);
                            return;
                        }
                    }
                    
                    // MODE 처음부터 다시 짜기!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
                    // JOIN -> PASSWORD 틀렸는데도 성공 메시지 뜨는 거 수정해야함
                    // MODE -> t, i 완벽
                    // MODE -> k, o, l 수정해야함
                    // TODO : copy MODE's response from other server

                    // send RPL_CHANNELMODEIS
                    successMessageToClient.mCommand = MODE;
                    successMessageToClient.mMessageTokens.clear();
                    successMessageToClient.mHasPrefix = true;
                    successMessageToClient.mMessageTokens.push_back(":"+clientData->getClientNickname() + "!" + clientData->getUsername() + "@" + clientData->getHostname());
                    successMessageToClient.mMessageTokens.push_back("MODE");
                    successMessageToClient.mMessageTokens.push_back(channel->getName());
                    successMessageToClient.mMessageTokens.push_back(mode);
                    // if ()

                    Server::sendMessagetoChannel(channel, successMessageToClient);

                    // when the mode is changed, send the message to all clients in the channel
                    Message nameReply = channel->getNameReply(&mServerAddress, clientData);
                    Message endOfNamesMessage = channel->getEndOfNames(&mServerAddress, clientData);

                    for (std::map<std::string, ClientData*>::iterator it = channel->getNickToClientDataMap().begin(); it != channel->getNickToClientDataMap().end(); it++)
                    {
                        it->second->getServerToClientSendQueue().push(nameReply);
                        it->second->getServerToClientSendQueue().push(endOfNamesMessage);
                    }
                }
            }
            break;

        case NOTICE: // < it's not in the RFC 1459, but it's in the RFC 2812, ONLY SERVER CAN USE THIS COMMAND

            break;

        default:
            Logger::log(WARNING, "Unknown command, sending ERR_UNKNOWNCOMMAND");
            errMessageToClient.mMessageTokens.push_back(ERR_UNKNOWNCOMMAND);
            errMessageToClient.mMessageTokens.push_back(":Unknown command");
            clientData->getServerToClientSendQueue().push(errMessageToClient);
            Server::logClientData(clientData);
            break;
        }
    }
    Logger::log(DEBUG, "executing message done");
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

bool Server::parseReceivedRequestFromClientData(ClientData* clientData)
{
    Message messageToExecute;

    std::string str = clientData->getReceivedString();
    // Logger::log(DEBUG, "Trying to parse message with : \"" + str + "\"");
    if (str.length() < 2)
    {
        // Logger::log(WARNING, "Message is not completed yet");
        // Server::logMessage(messageToExecute);
        // assert(false);
        return false;
    }
    else if (str.length() == 2 && str[0] == '\r' && str[1] == '\n')
    {
        // Logger::log(WARNING, "Empty message");
        // Server::logMessage(messageToExecute);
        // assert(false);
        return false;
    }

    // Logger::log(DEBUG, "Printing str : ");
    // logHasStrCRLF(str); // DEBUG

    std::string target("\r\n");
    std::size_t startPos;
    std::size_t endPos;

    // TODO : FIX THIS LOGIC, IT MUST HANDLE MULTIPLE "\r\n" IN A STRING
    size_t commandStartPos = 0;
    // Push back strings to messageToExecute's vector and erase it from the string

    std::queue<std::string> strQueue;
    std::string messageStr;
    while (!str.empty())
    {
        startPos = 0;
        endPos = str.find(target);
        if (endPos == std::string::npos)
        {
            // Logger::log(DEBUG, "handled Every message in the string, end tokenizing");
            break;
        }

        messageStr = str.substr(startPos, endPos - startPos);
        if (messageStr.length() == 0)
        {
            // Logger::log(WARNING, "Empty message, end tokenizing");
            // Server::logMessage(messageToExecute);
            // assert(false);
            break;
        }
        strQueue.push(messageStr);
        str.erase(startPos, endPos - startPos + 2);
    }

    if (strQueue.empty())
    {
        // Logger::log(WARNING, "Empty message, end tokenizing");
        // Server::logMessage(messageToExecute);
        // assert(false);
        return false;
    }

    // we should chunk the messageStr with ' ' and ':' for parsing
    while (!strQueue.empty())
    {
        messageStr = strQueue.front();
        strQueue.pop();
        std::string token;
        std::size_t tokenStartPos = 0;
        std::size_t tokenEndPos = messageStr.find(' ', tokenStartPos);
        while (tokenEndPos != std::string::npos)
        {
            // if the token starts with ':', it's the last token
            if (messageStr[tokenStartPos] == ':')
            {
                token = messageStr.substr(tokenStartPos, messageStr.length() - tokenStartPos);
                messageToExecute.mMessageTokens.push_back(token);
                break;
            }

            if (tokenEndPos == tokenStartPos)
            {
                break;
            }

            token = messageStr.substr(tokenStartPos, tokenEndPos - tokenStartPos);
            messageToExecute.mMessageTokens.push_back(token);
            tokenStartPos = tokenEndPos + 1;
            tokenEndPos = messageStr.find(' ', tokenStartPos);
        }
        token = messageStr.substr(tokenStartPos, messageStr.length() - tokenStartPos);
        messageToExecute.mMessageTokens.push_back(token);

        Server::logMessage(messageToExecute);
        // set clientData's receivedString
        Logger::log(DEBUG, "ClientData's receivedString : " + messageStr);
        Logger::log(DEBUG, "Erasing message from clientData's receivedString");
        clientData->setReceivedString(str);


        // check if the messageToExecute has prefix, it's always a NICKNAME
        if (messageToExecute.mMessageTokens[0][0] == ':')
        {
            // checking Nickname's validity
            if (messageToExecute.mMessageTokens[0].length() < 2)
            {
                Logger::log(WARNING, "Invalid messageToExecute");
                Server::logMessage(messageToExecute);
                Logger::log(WARNING, "Sending ERR_UNKNOWNCOMMAND");
                Message errMessageToClient;
                errMessageToClient.mMessageTokens.push_back(ERR_UNKNOWNCOMMAND);
                errMessageToClient.mMessageTokens.push_back(":Unknown command");
                clientData->getServerToClientSendQueue().push(errMessageToClient);
                assert(false);
                continue;
            }
            std::string nick = messageToExecute.mMessageTokens[0].substr(1, messageToExecute.mMessageTokens[0].length() - 1);
            if (mNickToClientGlobalMap.find(nick) != mNickToClientGlobalMap.end())
            {
                Logger::log(WARNING, "Nickname collision, sending ERR_NICKNAMEINUSE");
                Message errMessageToClient;
                errMessageToClient.mMessageTokens.push_back(ERR_NICKNAMEINUSE);
                errMessageToClient.mMessageTokens.push_back(":Nickname collision");
                clientData->getServerToClientSendQueue().push(errMessageToClient);
                assert(false);
                continue;
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
            errMessageToClient.mMessageTokens.push_back(ERR_UNKNOWNCOMMAND);
            errMessageToClient.mMessageTokens.push_back(":Unknown command");
            clientData->getServerToClientSendQueue().push(errMessageToClient);
            // assert(false);
            continue;
        }

        // Damn, Should we use map for this?
        if (messageToExecute.mMessageTokens[commandStartPos] == "PASS")
        {
            messageToExecute.mCommand = PASS;
            // TODO : ./ircserv 6667 "" to test this
            if (messageToExecute.mMessageTokens.size() != 2)
            {
                Logger::log(WARNING, "Invalid messageToExecute, PASS command must have 1 parameter");
                Logger::log(WARNING, "Disconnecting client");
                Server::logMessage(messageToExecute);
                Message errMessageToClient;
                errMessageToClient.mMessageTokens.push_back(ERR_NEEDMOREPARAMS);
                errMessageToClient.mMessageTokens.push_back("PASS");
                errMessageToClient.mMessageTokens.push_back("Not enough parameters");
                errMessageToClient.mMessageTokens.push_back("Password Missmatched, disconnecting...");
                clientData->getServerToClientSendQueue().push(errMessageToClient);

                const SOCKET_FD clientFD = clientData->getClientSocket();
                delete clientData;
                clientData = NULL;
                mFdToClientGlobalMap.erase(clientFD);
                close(clientFD);
                Logger::log(DEBUG, "Client disconnected");

                return false;
            }
            // <user>       ::= <nonwhite> { <nonwhite> }
            // <letter>     ::= 'a' ... 'z' | 'A' ... 'Z'
            // <number>     ::= '0' ... '9'
            // <special>    ::= '-' | '[' | ']' | '\' | '`' | '^' | '{' | '}'
            // <nonwhite>   ::= <any 8bit code except SPACE (0x20)>

            // check if the password is valid

            if (messageToExecute.mMessageTokens[commandStartPos + 1].length() > MAX_PASSWORD_LENGTH)
            {
                Logger::log(WARNING, "Password is too long, sending ERR_PASSWDMISMATCH");
                Logger::log(WARNING, "Disconnecting client");
                Server::logMessage(messageToExecute);
                Message errMessageToClient;
                errMessageToClient.mMessageTokens.push_back(ERR_PASSWDMISMATCH);
                errMessageToClient.mMessageTokens.push_back("PASS");
                errMessageToClient.mMessageTokens.push_back("Password is too long");
                errMessageToClient.mMessageTokens.push_back("Password Missmatched, disconnecting...");
                clientData->getServerToClientSendQueue().push(errMessageToClient);

                const SOCKET_FD clientFD = clientData->getClientSocket();
                delete clientData;
                clientData = NULL;
                mFdToClientGlobalMap.erase(clientFD);
                close(clientFD);
                Logger::log(DEBUG, "Client disconnected");

                return false;
            }



            clientData->getExecuteMessageQueue().push(messageToExecute);

            continue;

        }
        else if (messageToExecute.mMessageTokens[commandStartPos] == "NICK")
        {
            messageToExecute.mCommand = NICK;
            if (messageToExecute.mMessageTokens.size() == commandStartPos + 1)
            {
                Logger::log(WARNING, "Invalid messageToExecute");
                Server::logMessage(messageToExecute);
                Message errMessageToClient;
                errMessageToClient.mMessageTokens.push_back(ERR_NEEDMOREPARAMS);
                errMessageToClient.mMessageTokens.push_back("NICK");
                errMessageToClient.mMessageTokens.push_back("Not enough parameters");

                clientData->getServerToClientSendQueue().push(errMessageToClient);
                assert(false);
                continue;
            }
            std::map<std::string, ClientData*>::iterator nickIter;
            nickIter = mNickToClientGlobalMap.find(messageToExecute.mMessageTokens[commandStartPos + 1]);
            if (nickIter != mNickToClientGlobalMap.end())
            {
                Logger::log(WARNING, "Nickname collision, sending ERR_NICKCOLLISION");
                Server::logMessage(messageToExecute);
                Message errMessageToClient;
                errMessageToClient.mMessageTokens.push_back(ERR_NICKCOLLISION);
                errMessageToClient.mMessageTokens.push_back("Nickname collision");

                clientData->getServerToClientSendQueue().push(errMessageToClient);
                // assert(false);
                continue;
            }

            clientData->getExecuteMessageQueue().push(messageToExecute);
            return true;
        }
        else if (messageToExecute.mMessageTokens[commandStartPos] == "USER")
        {
            messageToExecute.mCommand = USER;
            if (messageToExecute.mMessageTokens.size() < commandStartPos + 4)
            {
                Logger::log(WARNING, "Invalid messageToExecute");
                Server::logMessage(messageToExecute);
                Message errMessageToClient;
                errMessageToClient.mMessageTokens.push_back(ERR_NEEDMOREPARAMS);
                errMessageToClient.mMessageTokens.push_back("USER");
                errMessageToClient.mMessageTokens.push_back("Not enough parameters");
                clientData->getServerToClientSendQueue().push(errMessageToClient);
                continue;
            }

            // check if the user input is valid
            if (clientData->getUsername().length() != 0 || clientData->getHostname().length() != 0 || clientData->getServername().length() != 0 || clientData->getRealname().length() != 0)
            {
                Logger::log(WARNING, "User input is invalid, sending ERROR");
                Server::logMessage(messageToExecute);
                // send ERR_ALREADYREGISTRED
                Message errMessageToClient;
                errMessageToClient.mMessageTokens.push_back("Ivalid user input");
                clientData->getServerToClientSendQueue().push(errMessageToClient);
                assert(false);
                continue;
            }

            clientData->getExecuteMessageQueue().push(messageToExecute);
            continue;
        }
        else if (messageToExecute.mMessageTokens[commandStartPos] == "JOIN")
        {
            messageToExecute.mCommand = JOIN;
            if (messageToExecute.mMessageTokens.size() == commandStartPos + 1)
            {
                Logger::log(WARNING, "Invalid messageToExecute");
                Server::logMessage(messageToExecute);
                Message errMessageToClient;
                errMessageToClient.mMessageTokens.push_back(ERR_NEEDMOREPARAMS);
                errMessageToClient.mMessageTokens.push_back("JOIN");
                errMessageToClient.mMessageTokens.push_back("Not enough parameters");
                clientData->getServerToClientSendQueue().push(errMessageToClient);
                // assert(false);
                continue;
            }


            clientData->getExecuteMessageQueue().push(messageToExecute);
            continue;
        }
        // args : <channel>{,<channel>} [<key>{,<key>}]
        else if (messageToExecute.mMessageTokens[commandStartPos] == "PART")
        {
            messageToExecute.mCommand = PART;
            if (messageToExecute.mMessageTokens.size() == commandStartPos + 1)
            {
                Logger::log(WARNING, "Invalid messageToExecute");
                Server::logMessage(messageToExecute);
                Message errMessageToClient;
                errMessageToClient.mMessageTokens.push_back(ERR_NEEDMOREPARAMS);
                errMessageToClient.mMessageTokens.push_back("PART");
                errMessageToClient.mMessageTokens.push_back("Not enough parameters");

                clientData->getServerToClientSendQueue().push(errMessageToClient);
                assert(false);
                continue;
            }

            if (messageToExecute.mMessageTokens[1] == "")
            {
                Logger::log(WARNING, "Invalid messageToExecute");
                Server::logMessage(messageToExecute);
                Message errMessageToClient;
                errMessageToClient.mMessageTokens.push_back(ERR_NEEDMOREPARAMS);
                errMessageToClient.mMessageTokens.push_back("PART");
                errMessageToClient.mMessageTokens.push_back("Not enough parameters");

                clientData->getServerToClientSendQueue().push(errMessageToClient);
                assert(false);
                continue;
            }


            clientData->getExecuteMessageQueue().push(messageToExecute);
            continue;
        }
        else if (messageToExecute.mMessageTokens[commandStartPos] == "PRIVMSG")
        {
            messageToExecute.mCommand = PRIVMSG;
            clientData->getExecuteMessageQueue().push(messageToExecute);
            continue;
        }
        // else if (messageToExecute.mMessageTokens[commandStartPos] == "PING")
        // {
        //     messageToExecute.mCommand = PING;
        //     clientData->getExecuteMessageQueue().push(messageToExecute);
        //     return true;
        // }
        // else if (messageToExecute.mMessageTokens[commandStartPos] == "PONG")
        // {
        //     messageToExecute.mCommand = PONG;
        //     clientData->getExecuteMessageQueue().push(messageToExecute);
        //     return true;
        // }
        else if (messageToExecute.mMessageTokens[commandStartPos] == "QUIT")
        {
            messageToExecute.mCommand = QUIT;
            messageToExecute.mMessageTokens.push_back("QUIT");

            if (messageToExecute.mMessageTokens.size() > commandStartPos + 1 && messageToExecute.mMessageTokens[commandStartPos + 1].length() > 0)
            {
                std::string reason;
                // should handle multi-word message, 
                // if the message starts with ':', it's the last token
                if (messageToExecute.mMessageTokens[commandStartPos + 1][0] == ':')
                {
                    reason = messageToExecute.mMessageTokens[commandStartPos + 1].substr(1, messageToExecute.mMessageTokens[commandStartPos + 1].length() - 1);
                }
                else
                {
                    reason = messageToExecute.mMessageTokens[commandStartPos + 1];
                }
                if (reason.length() > MAX_MESSAGE_LENGTH)
                {
                    Logger::log(WARNING, "Reason is too long, sending ERR_NEEDMOREPARAMS");
                    Message errMessageToClient;
                    errMessageToClient.mMessageTokens.push_back(ERR_NEEDMOREPARAMS);
                    errMessageToClient.mMessageTokens.push_back("QUIT");
                    errMessageToClient.mMessageTokens.push_back("Reason is too long, skipping");
                    errMessageToClient.mMessageTokens.push_back("Disconnecting...");
                    clientData->getServerToClientSendQueue().push(errMessageToClient);

                    clientData->getExecuteMessageQueue().push(messageToExecute);
                    // assert(false);
                    continue;
                }
            }
            clientData->getExecuteMessageQueue().push(messageToExecute);
            continue;
        }
        else if (messageToExecute.mMessageTokens[commandStartPos] == "KICK")
        {
            messageToExecute.mCommand = KICK;
            clientData->getExecuteMessageQueue().push(messageToExecute);
            continue;
        }
        else if (messageToExecute.mMessageTokens[commandStartPos] == "INVITE")
        {
            messageToExecute.mCommand = INVITE;
            clientData->getExecuteMessageQueue().push(messageToExecute);
            continue;
        }
        else if (messageToExecute.mMessageTokens[commandStartPos] == "TOPIC")
        {
            messageToExecute.mCommand = TOPIC;
            clientData->getExecuteMessageQueue().push(messageToExecute);
            continue;
        }
        else if (messageToExecute.mMessageTokens[commandStartPos] == "MODE")
        {
            messageToExecute.mCommand = MODE;
            clientData->getExecuteMessageQueue().push(messageToExecute);
            continue;
        }
        else if (messageToExecute.mMessageTokens[commandStartPos] == "NOTICE")
        {
            // it's client's command, not server's
            // ignore it

            // messageToExecute.mCommand = NOTICE;
            // clientData->getExecuteMessageQueue().push(messageToExecute);
            continue;
        }
        else
        {
            Logger::log(ERROR, "Invalid command, sending ERR_UNKNOWNCOMMAND");
            Message errMessageToClient;
            errMessageToClient.mMessageTokens.push_back(ERR_UNKNOWNCOMMAND);
            errMessageToClient.mMessageTokens.push_back(":Unknown command");
            clientData->getServerToClientSendQueue().push(errMessageToClient);
            continue;
        }

        // clientData->getExecuteMessageQueue().push(messageToExecute);
    }

    return true;
}

bool Server::isValidMessage(const Message& message) const
{
    size_t i = 0;
    if (message.mHasPrefix)
        i++;

    if (message.mMessageTokens.size() == 0)
        return false;
    if (message.mMessageTokens[0].length() == 0)
        return false;
    // for EXCEPTIONAL CASE : if the message has prefix, the first string must be NICKNAME
    // We know it's not a good way to implement, whatever.
    if (message.mHasPrefix)
    {
        if (message.mMessageTokens[0].length() < 2)
            return false;
    }
    while (i < message.mMessageTokens.size())
    {
        if (message.mMessageTokens[i].length() == 0)
            return false;
        if (message.mMessageTokens[i].length() > MAX_MESSAGE_LENGTH)
            return false;
        for (size_t j = 0; j < message.mMessageTokens[i].length(); j++)
        {
            if (message.mMessageTokens[i][j] == '\0' || message.mMessageTokens[i][j] == '\r' || message.mMessageTokens[i][j] == '\n')
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
    else
        assert(false);
}

void Server::logMessage(const Message& message) const
{
    Logger::log(DEBUG, "----------------- Beggining Message ----------------");
    Logger::log(DEBUG, "Command : " + ValToString(message.mCommand));
    Logger::log(DEBUG, "Has Prefix : " + ValToString(message.mHasPrefix));
    Logger::log(DEBUG, "Message Vector : ");
    for (size_t i = 0; i < message.mMessageTokens.size(); i++)
    {
        if (message.mMessageTokens[i].length() > 0)
            Logger::log(DEBUG, message.mMessageTokens[i]);
        for (size_t j = 0; j < message.mMessageTokens[i].length(); j++)
        {
            if (!isprint(message.mMessageTokens[i][j]) && message.mMessageTokens[i][j] != '\n')
                Logger::log(DEBUG, "Token has non-printable character!!!");
            if (message.mMessageTokens[i][j] == '\n')
                Logger::log(DEBUG, "Token has newline character!!!");
            if (message.mMessageTokens[i][j] == '\0')
                Logger::log(DEBUG, "Token has null character!!!");
            if (message.mMessageTokens[i][j] == 4)
                Logger::log(DEBUG, "Token has EOT character!!!");
        }
    }
    Logger::log(DEBUG, "================== End of Message ==================");
}

void Server::disconnectClientDataWithChannel(ClientData* clientData, Channel* channel)
{
    // when someone leaves the channel, send PART message to the every client
    Message successMessageToClient;
    successMessageToClient.mCommand = PART;
    successMessageToClient.mHasPrefix = true;
    successMessageToClient.mMessageTokens.clear();
    successMessageToClient.mMessageTokens.push_back(":" + clientData->getClientNickname());
    successMessageToClient.mMessageTokens.push_back("PART");
    successMessageToClient.mMessageTokens.push_back(channel->getName());
    successMessageToClient.mMessageTokens.push_back(clientData->getClientNickname());

    clientData->getServerToClientSendQueue().push(successMessageToClient);
    // remove clientData from channel
    channel->getNickToClientDataMap().erase(clientData->getClientNickname());
    channel->getNickToOperatorClientsMap().erase(clientData->getClientNickname());
    // remove channel from clientData
    clientData->getConnectedChannels().erase(channel->getName());
}

void Server::disconnectClientDataFromServer(ClientData* clientData)
{
    // delete clientData
    Logger::log(DEBUG, "Deleting clientData");
    Server::logClientData(clientData);
    const SOCKET_FD clientFD = clientData->getClientSocket();
    std::map <std::string, Channel*> connectedChannels = clientData->getConnectedChannels();
    for (std::map<std::string, Channel*>::iterator it = connectedChannels.begin(); it != connectedChannels.end(); it++)
    {
        it->second->getNickToClientDataMap().erase(clientData->getClientNickname());
        it->second->getNickToOperatorClientsMap().erase(clientData->getClientNickname());
        if (it->second->getNickToClientDataMap().empty())
        {
            delete it->second;
            it->second = NULL;
        }
    }
    Logger::log(DEBUG, clientData->getClientNickname() + " disconnected from Server!");

    // remove kevent from kqueue
    struct kevent evSet;
    EV_SET(&evSet, clientFD, EVFILT_READ, EV_DELETE, 0, 0, NULL);
    if (kevent(mhKqueue, &evSet, 1, NULL, 0, NULL) == -1)
    {
        Logger::log(ERROR, "kevent() failed");
        assert(false);
    }

    mNickToClientGlobalMap.erase(clientData->getClientNickname());
    delete clientData;
    clientData = NULL;
    mFdToClientGlobalMap.erase(clientFD);
    close(clientFD);
}

void Server::sendChannelJoinSucessMessageToClientData(ClientData* clientData, Channel* channel)
{
    Message successMessageToClient;

    // 332    RPL_TOPIC
    if (channel->getTopic().length() > 0)
    {
        successMessageToClient.mCommand = NONE;
        successMessageToClient.mMessageTokens.clear();
        successMessageToClient.mHasPrefix = true;

        // prifix = :address of the server
        successMessageToClient.mMessageTokens.push_back(":" + std::string(inet_ntoa(mServerAddress.sin_addr)));
        successMessageToClient.mMessageTokens.push_back("332");
        successMessageToClient.mMessageTokens.push_back(clientData->getClientNickname());
        successMessageToClient.mMessageTokens.push_back(channel->getName());
        successMessageToClient.mMessageTokens.push_back(":" + channel->getTopic());
        clientData->getServerToClientSendQueue().push(successMessageToClient);
    }
    // 331    RPL_NOTOPIC
    else if (channel->getTopic().length() == 0)
    {
        successMessageToClient.mCommand = NONE;
        successMessageToClient.mMessageTokens.clear();
        successMessageToClient.mHasPrefix = true;

        successMessageToClient.mMessageTokens.push_back(":" + std::string(inet_ntoa(mServerAddress.sin_addr)));
        successMessageToClient.mMessageTokens.push_back("331");
        successMessageToClient.mMessageTokens.push_back(clientData->getClientNickname());
        successMessageToClient.mMessageTokens.push_back(channel->getName());
        successMessageToClient.mMessageTokens.push_back(":No topic is set");
        clientData->getServerToClientSendQueue().push(successMessageToClient);
    }

    // 353    RPL_NAMREPLY
    Message nameReply = channel->getNameReply(&mServerAddress, clientData);

    clientData->getServerToClientSendQueue().push(nameReply);

    // 366    RPL_ENDOFNAMES

    Message endOfNames;

    endOfNames = channel->getEndOfNames(&mServerAddress, clientData);

    clientData->getServerToClientSendQueue().push(endOfNames);

}

void Server::sendMessagetoChannel(Channel* channel, const Message& message)
{
    for (std::map<std::string, ClientData*>::iterator it = channel->getNickToClientDataMap().begin(); it != channel->getNickToClientDataMap().end(); it++)
    {
        it->second->getServerToClientSendQueue().push(message);

        // kevent for sending message to client
        struct kevent evSet;
        EV_SET(&evSet, it->second->getClientSocket(), EVFILT_WRITE, EV_ADD, 0, 0, NULL);
        if (kevent(mhKqueue, &evSet, 1, NULL, 0, NULL) == -1)
        {
            Logger::log(ERROR, "kevent() failed");
            assert(false);
        }
    }
}
void Server::sendWelcomeMessageToClientData(ClientData* clientData)
{
    Message successMessageToClient;

    successMessageToClient.mCommand = NONE;
    successMessageToClient.mMessageTokens.clear();
    // RPL_WELCOME
    // :server 001 <nick> :Welcome to the Internet Relay Network <nick>!<user>@<host>
    successMessageToClient.mMessageTokens.push_back(RPL_WELCOME);
    successMessageToClient.mMessageTokens.push_back(clientData->getClientNickname());
    successMessageToClient.mMessageTokens.push_back(":Welcome to the Internet Relay Network " + clientData->getClientNickname() + "! " + clientData->getIp());
    clientData->getServerToClientSendQueue().push(successMessageToClient);

    // RPL_YOURHOST
    // :server 002 <nick> <servername> <version>
    successMessageToClient.mMessageTokens.clear();
    successMessageToClient.mMessageTokens.push_back(RPL_YOURHOST);
    successMessageToClient.mMessageTokens.push_back(clientData->getClientNickname());
    successMessageToClient.mMessageTokens.push_back(":Your host is " + std::string(inet_ntoa(mServerAddress.sin_addr)) + ", running version 0.0.1");
    clientData->getServerToClientSendQueue().push(successMessageToClient);

    // RPL_CREATED
    // :server 003 <nick> :This server was created <date>
    {
        successMessageToClient.mMessageTokens.clear();
        successMessageToClient.mMessageTokens.push_back(RPL_CREATED);
        successMessageToClient.mMessageTokens.push_back(clientData->getClientNickname());
        std::string timeNow = std::ctime(&mServerStartTime);
        timeNow.pop_back();
        successMessageToClient.mMessageTokens.push_back(":This server was created " + timeNow);
        clientData->getServerToClientSendQueue().push(successMessageToClient);
    }

    // RPL_MYINFO
    // :server 004 <nick> <servername> <version> <available umodes> <available cmodes> [<cmodes with param>]
    successMessageToClient.mMessageTokens.clear();
    successMessageToClient.mMessageTokens.push_back(RPL_MYINFO);
    successMessageToClient.mMessageTokens.push_back(SERVER_NAME);
    successMessageToClient.mMessageTokens.push_back(SERVER_VERSION);
    successMessageToClient.mMessageTokens.push_back("o");
    successMessageToClient.mMessageTokens.push_back("itkol");
    clientData->getServerToClientSendQueue().push(successMessageToClient);

    // skip 251 - 255

    // 375 RPL_MOTDSTART
    // :server 375 <nick> :- <server> Message of the day -
    successMessageToClient.mMessageTokens.clear();
    successMessageToClient.mMessageTokens.push_back(RPL_MOTDSTART);
    successMessageToClient.mMessageTokens.push_back(clientData->getClientNickname());
    successMessageToClient.mMessageTokens.push_back(":- " + std::string(inet_ntoa(mServerAddress.sin_addr)) + " Message of the day -");
    clientData->getServerToClientSendQueue().push(successMessageToClient);

    // 372 RPL_MOTD
    // :server 372 <nick> :- <text>
    successMessageToClient.mMessageTokens.clear();
    successMessageToClient.mMessageTokens.push_back(RPL_MOTD);
    successMessageToClient.mMessageTokens.push_back(clientData->getClientNickname());
    successMessageToClient.mMessageTokens.push_back(":알아 노십쇼");
    clientData->getServerToClientSendQueue().push(successMessageToClient);

    // 376 RPL_ENDOFMOTD
    // :server 376 <nick> :End of /MOTD command.
    successMessageToClient.mMessageTokens.clear();
    successMessageToClient.mMessageTokens.push_back(RPL_ENDOFMOTD);
    successMessageToClient.mMessageTokens.push_back(clientData->getClientNickname());
    successMessageToClient.mMessageTokens.push_back(":End of /MOTD command.");
    clientData->getServerToClientSendQueue().push(successMessageToClient);

}
