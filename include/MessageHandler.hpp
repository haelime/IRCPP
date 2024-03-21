#pragma once
#include <string>
#include <map>

#include "macro.hpp"
#include "ClientData.hpp"

struct Message
{
    std::string mReceivingChannelName;
    std::string mMessage;
    std::string mSender;
    std::string mReceiver;
};

class MessageHandler
{
public:
    MessageHandler() {};
    virtual ~MessageHandler() {};

    // find the clientData
    void assembleDataToMessage(std::pair<SOCKET_FD, std::string>& data, const std::map<SOCKET_FD, ClientData*> &clientDataMap)
    {
        std::map<SOCKET_FD, ClientData*>::const_iterator clientDataIter = clientDataMap.find(data.first);
        if (clientDataIter == clientDataMap.end())
        {
            std::cerr << "ClientData not found, closing socket\n";
            close(data.first);
            return;
        }
        ClientData* clientData = (*clientDataIter).second; // cuz it's map, it's O(logN)

        std::string dataString = data.second;
        clientData->appendData(dataString);
        if (isValidMessage(clientData->getReceivedData()))
        {
            Message message;

            // TODO : parse the message
            (void)message;
        }
        return;
    };

    bool isValidMessage(std::string& data)
    {
        // if the data is too small, we can't make a message
        if (data.size() < 2)
        {
            return false;
        }

        // if the data is too big, we should handle error
        if (data.size() > MAX_MESSAGE_LENGTH)
        {
            return false;
        }

        // if the data is not ended with \r\n, we can't make a message
        if (data[data.size() - 2] != '\r' || data[data.size() - 1] != '\n')
        {
            return false;
        }

        // if the data is ended with \r\n, we can make a message
        return true;
    };

private:
    void sendMessage()
    {
        // send message to all clients
    };

private:
    std::queue <Message> mMessageQueue;
};


