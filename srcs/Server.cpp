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

    int yes = 1;
    if (setsockopt(mServerListenSocket, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)
    {
        Logger::log(FATAL, "Failed to mod socket option");
        assert(0);
        return false;
    }

    // Bind listen socket
    Logger::log(DEBUG, "Server is binding socket...");
    if (SOCKET_ERROR == bind(mServerListenSocket, (const sockaddr*)&mServerAddress, mServerAddressLength))
    {
        Logger::log(FATAL, "Failed to bind socket");
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

                // Find the clientData
                Logger::log(DEBUG, "Finding clientData object");
                // TODO : change to .find() instead of operator[] for preventing creating new ClientData object when not found
                ClientData* clientData = mFdToClientGlobalMap[filteredEvents[i].ident]; // cuz it's map, it's O(logN)
                delete clientData;
                clientData = NULL;
                Logger::log(DEBUG, "ClientData object deleted");
                mFdToClientGlobalMap.erase(filteredEvents[i].ident);
                Logger::log(DEBUG, "Client removed from map");
                close(filteredEvents[i].ident);
                Logger::log(DEBUG, "Client socket closed");
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
                        close(filteredEvents[i].ident);
                        assert(0);
                        continue;
                    }

                    Server::logClientData(clientData);

                    // Client disconnected
                    if (recvMsgLength == 0)
                    {
                        Logger::log(INFO, "Client disconnected");

                        Server::logClientData(clientData);

                        // Delete clientData object
                        delete clientData;
                        clientData = NULL;
                        mFdToClientGlobalMap.erase(filteredEvents[i].ident);
                        close(filteredEvents[i].ident);
                        Logger::log(DEBUG, "ClientData object deleted");
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
                // Logger::log(DEBUG, "ClientData object found");

                // Make message to send from message tokens
                // :<Server Name> <Message> \r\n
                std::string sendMsg;
                if (clientData->getServerToClientSendQueue().empty())
                {
                    // Logger::log(ERROR, "ServerToClientSendQueue is empty, ignore sending message");
                    continue;
                }
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

                const int sendMsgLength = send(clientFD, sendMsg.c_str(), sendMsg.length(), 0);
                if (SOCKET_ERROR == sendMsgLength)
                {
                    Logger::log(ERROR, "Failed to send message to client");
                    std::perror("send");
                    close(clientFD);
                    assert(0);
                    continue;
                }

                // Pop message from queue
                clientData->getServerToClientSendQueue().pop();

                // Disable EVFILT_WRITE filter when the message is fully sent
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
            {
                SOCKET_FD clientFD;
                while (!mRecvedStrPerClientDataProcessQueue.empty())
                {
                    // send receivedRequest to clientData, and server will handle the message
                    clientFD = mRecvedStrPerClientDataProcessQueue.front();
                    mRecvedStrPerClientDataProcessQueue.pop();
                    Logger::log(DEBUG, "Parsing received message to clientData object");

                    std::map<SOCKET_FD, ClientData*>::const_iterator clientDataIter = mFdToClientGlobalMap.find(clientFD);
                    if (clientDataIter == mFdToClientGlobalMap.end())
                    {
                        Logger::log(WARNING, "ClientData not found");
                        continue;
                    }

                    ClientData* clientData = clientDataIter->second;

                    // add string to right clientData's receivedString

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


                    // executeParsedMessages(clientData);
                }

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
                clientData->setIsRegistered(true);
                clientData->setLastPingTime(time(NULL));

                break;
            }
            else
            {
                Logger::log(WARNING, "Invalid password, disconnecting client");
                Server::logMessage(messageToExecute);
                Message errMessageToClient;
                errMessageToClient.mMessageTokens.push_back(ERR_PASSWDMISMATCH);
                errMessageToClient.mMessageTokens.push_back(":*** Password Missmatched, disconnecting...");
                clientData->getServerToClientSendQueue().push(errMessageToClient);

                const SOCKET_FD clientFD = clientData->getClientSocket();
                delete clientData;
                clientData = NULL;
                mFdToClientGlobalMap.erase(clientFD);
                close(clientFD);
                Logger::log(DEBUG, "Client disconnected");

                break;
            }

        case NICK:

            //  If the server recieves an identical NICK from a client which is
            //  directly connected, it may issue an ERR_NICKCOLLISION to the local
            //  client, drop the NICK command, and not generate any kills.
            Logger::log(DEBUG, "executing NICK command from " + getIpFromClientData(clientData) + " with nickname " + messageToExecute.mMessageTokens[0]);

            successMessageToClient.mCommand = NOTICE;
            successMessageToClient.mMessageTokens.clear();
            successMessageToClient.mMessageTokens.push_back("NOTICE");
            successMessageToClient.mMessageTokens.push_back("AUTH");
            successMessageToClient.mMessageTokens.push_back(":*** Nickname accepted");
            clientData->getServerToClientSendQueue().push(successMessageToClient);

            clientData->setClientNickname(messageToExecute.mMessageTokens[paramStartPos]);
            Logger::log(INFO, "Client " + clientData->getClientNickname() + " set nickname to " + messageToExecute.mMessageTokens[0]);
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
                else if (channelName.length() > MAX_CHANNEL_NAME_LENGTH)
                {
                    Logger::log(ERROR, "Channel name is too long, sending ERR_NOSUCHCHANNEL");
                    errMessageToClient.mMessageTokens.push_back(ERR_NOSUCHCHANNEL);
                    errMessageToClient.mMessageTokens.push_back(":Channel name is too long");
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


                std::map<std::string, Channel*>::iterator channelIter = mNameToChannelGlobalMap.find(messageToExecute.mMessageTokens[paramStartPos]);
                if (channelIter == mNameToChannelGlobalMap.end())
                {
                    Logger::log(DEBUG, "Channel not found, creating new channel");
                    Channel* newChannel = new Channel(channelNames[i]);
                    mNameToChannelGlobalMap[channelNames[i]] = newChannel;
                    if (channelKeys.size() > i)
                    {
                        newChannel->setPassword(channelKeys[i]);
                        connectClientDataWithChannel(clientData, newChannel, channelKeys[i]);
                        Logger::log(INFO, "Channel created with password");
                        Server::sendChannelJoinSucessMessageToClientData(clientData, newChannel);
                        Logger::log(INFO, clientData->getClientNickname() + " joined Channel " + newChannel->getName() + " with password");
                        newChannel->getNickToOperatorClientsMap()[clientData->getClientNickname()] = clientData;
                        Server::logClientData(clientData);

                        continue;
                    }
                    connectClientDataWithChannel(clientData, newChannel);
                    Server::sendChannelJoinSucessMessageToClientData(clientData, newChannel);
                    Logger::log(INFO, "Channel created without password");
                    Logger::log(INFO, clientData->getClientNickname() + " joined Channel " + newChannel->getName() + " with password");
                    Server::logClientData(clientData);
                    newChannel->getNickToOperatorClientsMap()[clientData->getClientNickname()] = clientData;
                }
                else
                {
                    Channel* channel = channelIter->second;
                    if (channel == NULL)

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
                            connectClientDataWithChannel(clientData, channel, channelKeys[i]);

                            successMessageToClient.mCommand = NONE;
                            successMessageToClient.mMessageTokens.clear();
                            successMessageToClient.mMessageTokens.push_back(RPL_TOPIC);
                            successMessageToClient.mMessageTokens.push_back(channel->getName());
                            successMessageToClient.mMessageTokens.push_back(channel->getTopic());
                            clientData->getServerToClientSendQueue().push(successMessageToClient);
                            Logger::log(INFO, clientData->getClientNickname() + "joined Channel " + channel->getName() + " with password");
                            Server::logClientData(clientData);
                            channel->getNickToOperatorClientsMap()[clientData->getClientNickname()] = clientData;
                            Server::sendChannelJoinSucessMessageToClientData(clientData, channel);
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

                    connectClientDataWithChannel(clientData, channel);

                    successMessageToClient.mCommand = NONE;
                    successMessageToClient.mMessageTokens.clear();
                    successMessageToClient.mMessageTokens.push_back(RPL_TOPIC);
                    successMessageToClient.mMessageTokens.push_back(channel->getName());
                    successMessageToClient.mMessageTokens.push_back(channel->getTopic());
                    clientData->getServerToClientSendQueue().push(successMessageToClient);

                    Logger::log(INFO, clientData->getClientNickname() + "joined Channel " + channel->getName());
                    Server::logClientData(clientData);
                    channel->getNickToOperatorClientsMap()[clientData->getClientNickname()] = clientData;
                    Server::sendChannelJoinSucessMessageToClientData(clientData, channel);
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

            // :WiZ PART #twilight_zone        ; leave channel "#twilight_zone"

            // parse channel names
            Logger::log(DEBUG, "executing PART command from");
            Server::logClientData(clientData);
            Server::logMessage(messageToExecute);

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

            // remove channel from clientData
            for (size_t i = 0;i < channelNames.size(); i++)
            {
                std::map <std::string, Channel*>::iterator channelIter = mNameToChannelGlobalMap.find(channelNames[i]);

                Channel* channel = channelIter->second;

                // erase channel if no one is in it
                if (channel->getNickToClientDataMap().empty())
                {
                    mNameToChannelGlobalMap.erase(channelNames[i]);
                }

                clientData->getConnectedChannels().erase(channelNames[i]);

                // send PART message to channel
                Message clientPartMessage;
                clientPartMessage.mCommand = PART;
                clientPartMessage.mMessageTokens.clear();
                clientPartMessage.mHasPrefix = true;
                clientPartMessage.mMessageTokens.push_back(clientData->getClientNickname());
                clientPartMessage.mMessageTokens.push_back("PART");
                clientPartMessage.mMessageTokens.push_back(channelNames[i]);
                clientPartMessage.mMessageTokens.push_back(clientData->getClientNickname());
                Server::sendMessagetoChannel(channel, clientPartMessage);

                // send PART message to client
                successMessageToClient.mCommand = NONE;
                successMessageToClient.mMessageTokens.clear();
                successMessageToClient.mHasPrefix = true;
                successMessageToClient.mMessageTokens.push_back(clientData->getClientNickname());
                successMessageToClient.mMessageTokens.push_back("PART");
                successMessageToClient.mMessageTokens.push_back(channelNames[i]);
                successMessageToClient.mMessageTokens.push_back(clientData->getClientNickname());
                clientData->getServerToClientSendQueue().push(successMessageToClient);
            }

            Logger::log(INFO, clientData->getClientNickname() + " left channels");

            break;
        case PRIVMSG:

            // Command: PRIVMSG
            // Parameters: <receiver>{,<receiver>} <text to be sent>

            // PRIVMSG is used to send private messages between users.  <receiver>
            // is the nickname of the receiver of the message.  <receiver> can also
            // be a list of names or channels separated with commas.

            // The <receiver> parameter may also me a host mask  (#mask or $mask).   
            // In  both cases the server will only send the PRIVMSG
            // to those who have a server or host matching the mask.  The mask  must
            // have at  least  1  (one)  "."  in it and no wildcards following the
            // last ".".  This requirement exists to prevent people sending messages
            // to  "#*"  or "$*",  which  would  broadcast  to  all  users; from
            // experience, this is abused more than used responsibly and properly.
            // Wildcards are  the  '*' and  '?'   characters.   This  extension  to
            // the PRIVMSG command is only available to Operators.

            // Numeric Replies:

            //         ERR_NORECIPIENT                 ERR_NOTEXTTOSEND
            //         ERR_CANNOTSENDTOCHAN            ERR_NOTOPLEVEL
            //         ERR_WILDTOPLEVEL                ERR_TOOMANYTARGETS
            //         ERR_NOSUCHNICK
            //         RPL_AWAY

            // Examples:

            // :Angel PRIVMSG Wiz :Hello are you receiving this message ?
            //                                 ; Message from Angel to Wiz.

            // PRIVMSG Angel :yes I'm receiving it !receiving it !'u>(768u+1n) .br ;
            //                                 Message to Angel.

            Logger::log(DEBUG, "executing PRIVMSG command from");
            Server::logClientData(clientData);
            Server::logMessage(messageToExecute);

            /** [ ]
             * <receiver> {, <receiver>} <text to be sent>
             *  <수신자닉네임>
             * 1) 이름 | 해널 목록 | 
             *    호스트 마스크(#) | 서버 마스크($) -> 마스크가 일치한 유저에게만 보낼 수 있음
             *      => MASK: 적어도 하나의 Dot'.'
             *               
             * */
            


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

                if (mNameToChannelGlobalMap.find(channelName) == mNameToChannelGlobalMap.end())
                {
                    Logger::log(ERROR, "Channel not found, sending ERR_NOSUCHCHANNEL");
                    errMessageToClient.mMessageTokens.push_back(ERR_NOSUCHCHANNEL);
                    errMessageToClient.mMessageTokens.push_back(":Channel not found");
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

                // check client is operator
                Channel* channel = mNameToChannelGlobalMap.find(channelName)->second;
                // if (channel->getOperatorClient() != clientData)
                // {
                //     Logger::log(ERROR, "Client is not operator, sending ERR_CHANOPRIVSNEEDED");
                //     errMessageToClient.mMessageTokens.push_back(ERR_CHANOPRIVSNEEDED);
                //     errMessageToClient.mMessageTokens.push_back("Client is not operator");
                //     clientData->getServerToClientSendQueue().push(errMessageToClient);
                //     Server::logClientData(clientData);
                //     return;
                // }

                if (channel->getNickToClientDataMap().find(userToKick) == channel->getNickToClientDataMap().end())
                {
                    Logger::log(ERROR, "User not found in the channel, sending ERR_NOSUCHNICK");
                    errMessageToClient.mMessageTokens.push_back(ERR_NOSUCHNICK);
                    errMessageToClient.mMessageTokens.push_back(":User not found in the channel");
                    clientData->getServerToClientSendQueue().push(errMessageToClient);
                    Server::logClientData(clientData);
                    return;
                }

                // remove user from channel
                ClientData* clientToKick = channel->getNickToClientDataMap().find(userToKick)->second;
                channel->getNickToClientDataMap().erase(userToKick);
                if (channel->getNickToClientDataMap().empty())
                {
                    mNameToChannelGlobalMap.erase(channelName);
                }
                clientToKick->getConnectedChannels().erase(channelName);

                successMessageToClient.mCommand = NONE;
                successMessageToClient.mMessageTokens.clear();
                successMessageToClient.mMessageTokens.push_back("KICK");
                successMessageToClient.mMessageTokens.push_back(channelName);
                successMessageToClient.mMessageTokens.push_back(userToKick);
                successMessageToClient.mMessageTokens.push_back(":Kicked from channel");
                clientData->getServerToClientSendQueue().push(successMessageToClient);
            }
            break;

            // NOT TESTED YET!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        case INVITE:
            // ERR_NEEDMOREPARAMS              ERR_NOSUCHNICK
            // ERR_NOTONCHANNEL               ERR_USERONCHANNEL
            // ERR_CHANOPRIVSNEEDED

            // INVITE <channel> <user>
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
                std::string channelName = messageToExecute.mMessageTokens[paramStartPos];

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

                if (channel->getNickToClientDataMap().find(messageToExecute.mMessageTokens[paramStartPos + 1]) != channel->getNickToClientDataMap().end())
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

                ClientData* invitedClient = mNickToClientGlobalMap.find(messageToExecute.mMessageTokens[paramStartPos + 1])->second;

                if (invitedClient == NULL)
                {
                    Logger::log(ERROR, "User not found, sending ERR_NOSUCHNICK");
                    errMessageToClient.mMessageTokens.push_back(ERR_NOSUCHNICK);
                    errMessageToClient.mMessageTokens.push_back(":User not found");
                    clientData->getServerToClientSendQueue().push(errMessageToClient);
                    Server::logClientData(clientData);
                    return;
                }

                invitedClient->getServerToClientSendQueue().push(messageToExecute);

                successMessageToClient.mCommand = NONE;
                successMessageToClient.mMessageTokens.clear();
                successMessageToClient.mMessageTokens.push_back("INVITE");
                successMessageToClient.mMessageTokens.push_back(channelName);
                successMessageToClient.mMessageTokens.push_back(messageToExecute.mMessageTokens[paramStartPos + 1]);
                successMessageToClient.mMessageTokens.push_back(":Invited to channel");
                clientData->getServerToClientSendQueue().push(successMessageToClient);

                Server::connectClientDataWithChannel(invitedClient, channel);

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
                successMessageToClient.mMessageTokens.push_back(clientData->getClientNickname());
                successMessageToClient.mMessageTokens.push_back(channel->getName());
                successMessageToClient.mMessageTokens.push_back(channel->getTopic());
                clientData->getServerToClientSendQueue().push(successMessageToClient);
            }
            else
            {
                // set the topic
                channel->setTopic(messageToExecute.mMessageTokens[paramStartPos + 1]);
                successMessageToClient.mCommand = TOPIC;
                successMessageToClient.mMessageTokens.clear();
                successMessageToClient.mHasPrefix = true;
                successMessageToClient.mMessageTokens.push_back(clientData->getClientNickname());
                successMessageToClient.mMessageTokens.push_back("TOPIC");
                successMessageToClient.mMessageTokens.push_back(channel->getName());
                successMessageToClient.mMessageTokens.push_back(channel->getTopic());
                clientData->getServerToClientSendQueue().push(successMessageToClient);
            }
        }

        break;

        // NOT TESTED YET!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        case MODE:

        {//     Command: MODE
        // Parameters: <channel> *( ( "-" / "+" ) *<modes> *<modeparams> )

        // The MODE command is provided so that users may query and change the
        // characteristics of a channel.  For more details on available modes
        // and their uses, see "Internet Relay Chat: Channel Management" [IRC-
        // CHAN].  Note that there is a maximum limit of three (3) changes per
        // command for modes that take a parameter.

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
            std::string modes = messageToExecute.mMessageTokens[paramStartPos + 1];
            std::string modeParams;
            if (messageToExecute.mMessageTokens.size() > paramStartPos + 2)
            {
                modeParams = messageToExecute.mMessageTokens[paramStartPos + 2];
            }

            // check if the modes are valid
            for (size_t i = 0; i < modes.length(); i++)
            {
                if (modes[i] != '+' && modes[i] != '-')
                {
                    Logger::log(ERROR, "Invalid mode, sending ERR_UNKNOWNMODE");
                    errMessageToClient.mMessageTokens.push_back(ERR_UNKNOWNMODE);
                    errMessageToClient.mMessageTokens.push_back(":Invalid mode");
                    clientData->getServerToClientSendQueue().push(errMessageToClient);
                    Server::logClientData(clientData);
                    return;
                }
            }

/*maxlenght */
            // SET MODES
            for (size_t i = 0; i < modes.length(); i++)
            {
                if (modes[i] == '+')
                {
                    // set mode
                    switch (modes[i + 1])
                    {
                    case 'i':
                        channel->setInviteOnly(true);
                        break;
                    case 't':
                        channel->setTopicRestricted(true);
                        break;
                    case 'k':
                        if (modeParams.length() == 0)
                        {
                            Logger::log(ERROR, "Channel key is empty, sending ERR_KEYSET");
                            errMessageToClient.mMessageTokens.push_back(ERR_KEYSET);
                            errMessageToClient.mMessageTokens.push_back(":Channel key is empty");
                            clientData->getServerToClientSendQueue().push(errMessageToClient);
                            Server::logClientData(clientData);
                            return;
                        }
                        channel->setPassword(modeParams);
                        break;
                    case 'o':
                        // give operator privilege
                        if (channel->getNickToOperatorClientsMap().find(modeParams) == channel->getNickToOperatorClientsMap().end())
                        {
                            channel->getNickToOperatorClientsMap()[modeParams] = mNickToClientGlobalMap.find(modeParams)->second;
                        }
                        break;
                    case 'l':
                        if (modeParams.length() == 0)
                        {
                            Logger::log(ERROR, "User limit is empty, sending ERR_NEEDMOREPARAMS");
                            errMessageToClient.mMessageTokens.push_back(ERR_NEEDMOREPARAMS);
                            errMessageToClient.mMessageTokens.push_back(":User limit is empty");
                            clientData->getServerToClientSendQueue().push(errMessageToClient);
                            Server::logClientData(clientData);
                            return;
                        }
                        channel->setUserLimit(atoi(modeParams.c_str()));
                        break;
                    default:
                        Logger::log(ERROR, "Invalid mode, sending ERR_UNKNOWNMODE");
                        errMessageToClient.mMessageTokens.push_back(ERR_UNKNOWNMODE);
                        errMessageToClient.mMessageTokens.push_back(":Invalid mode");
                        clientData->getServerToClientSendQueue().push(errMessageToClient);
                        Server::logClientData(clientData);
                        return;
                    }
                }
                else if (modes[i] == '-')
                {
                    // remove mode
                    switch (modes[i + 1])
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
                        if (channel->getNickToOperatorClientsMap().find(modeParams) != channel->getNickToOperatorClientsMap().end())
                        {
                            channel->getNickToOperatorClientsMap().erase(modeParams);
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
                        return;
                    }
                }

                // send RPL_CHANNELMODEIS
                successMessageToClient.mCommand = NONE;
                successMessageToClient.mMessageTokens.clear();
                successMessageToClient.mMessageTokens.push_back(RPL_CHANNELMODEIS);
                successMessageToClient.mMessageTokens.push_back(channel->getName());
                successMessageToClient.mMessageTokens.push_back(channel->getMode());
                clientData->getServerToClientSendQueue().push(successMessageToClient);

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
    Logger::log(DEBUG, "Trying to parse message with : \"" + str + "\"");
    if (str.length() < 2)
    {
        // Logger::log(WARNING, "Message is not completed yet");
        // Server::logMessage(messageToExecute);
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
            Logger::log(DEBUG, "handled Every message in the string, end tokenizing");
            break;
        }

        messageStr = str.substr(startPos, endPos - startPos);
        if (messageStr.length() == 0)
        {
            Logger::log(WARNING, "Empty message, end tokenizing");
            Server::logMessage(messageToExecute);
            // assert(false);
            break;
        }
        strQueue.push(messageStr);
        str.erase(startPos, endPos - startPos + 2);
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
                Logger::log(WARNING, "Nickname collision, sending ERR_NICKCOLLISION");
                Message errMessageToClient;
                errMessageToClient.mMessageTokens.push_back(ERR_NICKCOLLISION);
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
                assert(false);
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
                assert(false);
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
    Message successMessageToClient;
    successMessageToClient.mCommand = JOIN;
    successMessageToClient.mMessageTokens.clear();
    successMessageToClient.mMessageTokens.push_back("JOIN");
    successMessageToClient.mMessageTokens.push_back(channel->getName());
    successMessageToClient.mMessageTokens.push_back(clientData->getClientNickname());
    clientData->getServerToClientSendQueue().push(successMessageToClient);

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
    successMessageToClient.mMessageTokens.push_back(":"+clientData->getClientNickname());
    successMessageToClient.mMessageTokens.push_back("PART");
    successMessageToClient.mMessageTokens.push_back(channel->getName());
    successMessageToClient.mMessageTokens.push_back(clientData->getClientNickname());

    clientData->getServerToClientSendQueue().push(successMessageToClient);
    // remove clientData from channel
    channel->getNickToClientDataMap().erase(clientData->getClientNickname());
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

    delete clientData;
    clientData = NULL;
    mFdToClientGlobalMap.erase(clientFD);
    close(clientFD);
}

void Server::sendChannelJoinSucessMessageToClientData(ClientData* clientData, Channel* channel)
{
    Message successMessageToClient;
    successMessageToClient.mCommand = JOIN;
    successMessageToClient.mHasPrefix = true;
    successMessageToClient.mMessageTokens.clear();
    successMessageToClient.mMessageTokens.push_back(":"+clientData->getClientNickname());
    successMessageToClient.mMessageTokens.push_back("JOIN");
    successMessageToClient.mMessageTokens.push_back(channel->getName());
    clientData->getServerToClientSendQueue().push(successMessageToClient);

    // 332    RPL_TOPIC
    if (channel->getTopic().length() > 0)
    {
        successMessageToClient.mCommand = JOIN;
        successMessageToClient.mMessageTokens.clear();
        successMessageToClient.mHasPrefix = true;
        successMessageToClient.mMessageTokens.push_back(":"+clientData->getClientNickname());
        successMessageToClient.mMessageTokens.push_back("332");
        successMessageToClient.mMessageTokens.push_back(clientData->getClientNickname());
        successMessageToClient.mMessageTokens.push_back(channel->getName());
        successMessageToClient.mMessageTokens.push_back(channel->getTopic());
        clientData->getServerToClientSendQueue().push(successMessageToClient);
    }
    // 331    RPL_NOTOPIC
    else if (channel->getTopic().length() == 0)
    {
        successMessageToClient.mCommand = JOIN;
        successMessageToClient.mMessageTokens.clear();
        successMessageToClient.mHasPrefix = true;
        successMessageToClient.mMessageTokens.push_back(":"+clientData->getClientNickname());
        successMessageToClient.mMessageTokens.push_back("331");
        successMessageToClient.mMessageTokens.push_back(clientData->getClientNickname());
        successMessageToClient.mMessageTokens.push_back(channel->getName());
        successMessageToClient.mMessageTokens.push_back("No topic is set");
        clientData->getServerToClientSendQueue().push(successMessageToClient);
    }

    // 353    RPL_NAMREPLY
    std::string nickList = ":";
    for (std::map<std::string, ClientData*>::iterator it = channel->getNickToClientDataMap().begin(); it != channel->getNickToClientDataMap().end(); it++)
    {
        if (nickList.length() + it->first.length() > MAX_MESSAGE_LENGTH)
        {
            successMessageToClient.mCommand = JOIN;
            successMessageToClient.mHasPrefix = true;
            successMessageToClient.mMessageTokens.clear();
            successMessageToClient.mMessageTokens.push_back(":"+clientData->getClientNickname());
            successMessageToClient.mMessageTokens.push_back("353");
            successMessageToClient.mMessageTokens.push_back(clientData->getClientNickname());
            successMessageToClient.mMessageTokens.push_back("=@");
            successMessageToClient.mMessageTokens.push_back(channel->getName());
            successMessageToClient.mMessageTokens.push_back(nickList);
            clientData->getServerToClientSendQueue().push(successMessageToClient);
            nickList.clear();
        }
        // ADD CHANNEL OPERATOR LOGIC HERE +@
        // nickList += it->second->getConnectedChannels().find(channel->getName()->first);
        nickList += it->first + " ";
    }

    if (nickList.length() > 0)
    {
        successMessageToClient.mCommand = JOIN;
        successMessageToClient.mHasPrefix = true;
        successMessageToClient.mMessageTokens.clear();
        successMessageToClient.mMessageTokens.push_back(":"+clientData->getClientNickname());
        successMessageToClient.mMessageTokens.push_back("353");
        successMessageToClient.mMessageTokens.push_back(clientData->getClientNickname());
        successMessageToClient.mMessageTokens.push_back("=@");
        successMessageToClient.mMessageTokens.push_back(channel->getName());
        successMessageToClient.mMessageTokens.push_back(nickList);
        clientData->getServerToClientSendQueue().push(successMessageToClient);
    }

    // 366   RPL_ENDOFNAMES
    successMessageToClient.mCommand = JOIN;
    successMessageToClient.mHasPrefix = true;
    successMessageToClient.mMessageTokens.clear();
    successMessageToClient.mMessageTokens.push_back(":"+clientData->getClientNickname());
    successMessageToClient.mMessageTokens.push_back("366");
    successMessageToClient.mMessageTokens.push_back(clientData->getClientNickname());
    successMessageToClient.mMessageTokens.push_back(channel->getName());
    successMessageToClient.mMessageTokens.push_back("End of /NAMES list");

}
void Server::sendMessagetoChannel(Channel* channel, const Message& message)
{
    for (std::map<std::string, ClientData*>::iterator it = channel->getNickToClientDataMap().begin(); it != channel->getNickToClientDataMap().end(); it++)
    {
        it->second->getServerToClientSendQueue().push(message);
    }
}

/*[ ] sendMessagetoClient : 범용성있게끔 만들기 */