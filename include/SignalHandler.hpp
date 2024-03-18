#pragma once

#include <csignal>

// if server user wants to stop server, then server should stop and close all sockets
class SignalHandler
{
    public:
        SignalHandler();
        ~SignalHandler();

    public:
        void setSignals(void)
        {
            // TODO : close all sockets when receive sigint, sigterm, sigkill

            // Should we handle every signals to protect server?

            // SIGINT : ctrl + c
            // SIGTERM : ctrl + \
            // SIGKILL : kill -9

            // signal(SIGINT, signalHandler);
            // signal(SIGTERM, signalHandler);
            // signal(SIGKILL, signalHandler);
            
            

        };
        bool isServerRunning(void);

    private:
        static void closeEverySockets(int signal);
        static bool mServerRunning;
};


        