#pragma once

#include <csignal>
#include <string>
#include <iostream>
#include <map>
#include <utility>
#include "Server.hpp"
#include "Channel.hpp"
#include "ClientData.hpp"

// if server user wants to stop server, then server should stop and close all sockets
class SignalHandler
{
public:
    ~SignalHandler() {};

public:
    static void setSignals(Server &server);

private:
    SignalHandler(){};
    SignalHandler(const SignalHandler &src){ (void) src; };
    SignalHandler& operator=(const SignalHandler& src) { (void)src; return *this; };

    static void handleSigInt(int signal);

    static Server *mServer;
};
