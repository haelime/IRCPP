#pragma once

#include <string>
#include <iostream>
#include <fstream>
#include <sstream>
#include <ctime>

#include "AnsiColorDefines.hpp"

enum LogLevel
{
    DEFAULT,
    INFO,
    WARNING,
    ERROR,
    DEBUG,
    FATAL
};

class Logger
{
public:
    static void setFileLogging(const std::string& fileName);
    static void setConsoleLogging(bool isConsoleLogging);
    static void closeFileLogging();

    static void log(LogLevel logLevel, const std::string& logMessage);

private:
    static void logToFile(const std::string& logMessage);
    static void logToConsole(const std::string& logMessage, bool isCerr);
    static void logEmptyString(LogLevel logLevel);

private:
    Logger();
    virtual ~Logger();

    static bool             mIsFileLogging;
    static bool             mIsConsoleLogging;
    static bool             mIsCerr;

    static std::string      mFileName;
    static std::ofstream    logFile;
};