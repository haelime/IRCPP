#pragma once

#include <string>
#include <iostream>
#include <fstream>
#include <sstream>
#include <ctime>

#include "AnsiColorDefines.hpp"

// Integers
template <typename T>
std::string ValToString(const T value)
{
    std::ostringstream oss;
    oss << value;
    return oss.str();
}

// Hexadecimal
template <typename T>
std::string ValToStringByHex(const T value)
{
    std::ostringstream oss;
    oss << std::hex << value;
    return oss.str();
}


typedef unsigned int LogLevel;

#define DEFAULT (1)
#define DEBUG   (2)
#define INFO    (4)
#define WARNING (8)
#define ERROR   (16)
#define FATAL   (32)

#define LOG_DEBUG(logMessage) Logger::log(DEBUG, logMessage)
#define LOG_INFO(logMessage) Logger::log(INFO, logMessage)
#define LOG_WARNING(logMessage) Logger::log(WARNING, logMessage)
#define LOG_ERROR(logMessage) Logger::log(ERROR, logMessage)
#define LOG_FATAL(logMessage) Logger::log(FATAL, logMessage)

// enum LogLevel
// {
//     DEFAULT,
//     DEBUG,
//     INFO,
//     WARNING,
//     ERROR,
//     FATAL
// };

class Logger
{
public:
    static void setFileLogging(const std::string& fileName);
    static void setConsoleLogging(const bool isConsoleLogging);
    static void closeFileLogging();

    static void setLogLevelLimit(const LogLevel logLevelLimit);

    static void log(const LogLevel logLevel, const std::string& logMessage);

private:
    static void logToFile(const LogLevel logLevel, const std::string& logMessage);
    static void logToConsole(const LogLevel logLevel, const std::string& logMessage);

    // to print colorful string, starting with cool LogLevels
    // it only prints the logLevel string and " "
    static void logEmptyString(const LogLevel logLevel);

    static const std::string& getLogLevelString(const LogLevel logLevel);
    static const std::string& getLogLevelColor(const LogLevel logLevel);

private:
    Logger();
    virtual ~Logger();

    static bool             mIsFileLogging;
    static bool             mIsConsoleLogging;
    static bool             mIsCerr;

    static unsigned int     mLogLevelLimit;

    static std::string      mFileName;
    static std::ofstream    logFile;

    static std::string      mLogLevelString;
    static std::string      mLogColor;
};