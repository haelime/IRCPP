#include <cassert>

#include "Logger.hpp"

// There is A LOT to REFACTOR here.

bool             Logger::mIsFileLogging;
bool             Logger::mIsConsoleLogging;
bool             Logger::mIsCerr;
std::string      Logger::mFileName;
std::ofstream    Logger::logFile;
LogLevel         Logger::mLogLevel;
std::string      Logger::mLogLevelString;
std::string      Logger::mLogColor;

// probably we need to add (bool isFileLogging) too
void Logger::setFileLogging(const std::string& fileName)
{
    mIsFileLogging = true;
    mFileName = fileName;
    logFile.open(mFileName.c_str(), std::ios::out | std::ios::app);
    if (logFile.fail())
    {
        Logger::log(ERROR, "Failed to open log file, logging on console only");
        mIsFileLogging = false;
        assert(false);
    }
}

void Logger::setConsoleLogging(const bool isConsoleLogging)
{
    mIsConsoleLogging = isConsoleLogging;
}

void Logger::setLogLevel(const LogLevel logLevel)
{
    Logger::mLogLevel = logLevel;
}

void Logger::closeFileLogging()
{
    if (mIsFileLogging)
    {
        mIsFileLogging = false;

        Logger::log(INFO, "Closing log file");
        logFile.close();
    }
}

void Logger::log(const LogLevel logLevel, const std::string& logMessage)
{
    if (logMessage.empty())
    {
        logEmptyString(logLevel);
        return;
    }

    if (mIsFileLogging && (mLogLevel & logLevel))
        logToFile(logLevel, logMessage);

    if (mIsConsoleLogging && (mLogLevel & logLevel))
        logToConsole(logLevel, logMessage);
}

void Logger::logToFile(const LogLevel logLevel, const std::string& logMessage)
{
    const std::string logLevelString = Logger::getLogLevelString(logLevel);

    std::stringstream ss;

    // Sadly, file cannot render ANSI color
    ss << "[" << logLevelString << "]";

    // [2021-01-01 12:00:00]
    std::time_t currentTime = std::time(0);
    std::tm* now = std::localtime(&currentTime);
    ss << "[" << now->tm_year + 1900 << "-" << now->tm_mon + 1 << "-" << now->tm_mday << " " << now->tm_hour << ":" << now->tm_min << ":" << now->tm_sec << "]";
    ss << " ";
    ss << logMessage;

    if (!logFile.is_open())
    {
        Logger::log(ERROR, "Failed log to file, logging on console only");
        mIsFileLogging = false;
        return;
    }
    logFile << ss.str() << std::endl;
}

void Logger::logToConsole(const LogLevel logLevel, const std::string& logMessage)
{
    const std::string logLevelString = getLogLevelString(logLevel);
    const std::string color = getLogLevelColor(logLevel);

    std::stringstream ss;

    ss << color << "[" << logLevelString << "]" << ANSI_RESET;

    ss << " ";

    // [2021-01-01 12:00:00]
    std::time_t currentTime = std::time(0);
    std::tm* now = std::localtime(&currentTime);
    ss << "[" << now->tm_year + 1900 << "-" << now->tm_mon + 1 << "-" << now->tm_mday << " " << now->tm_hour << ":" << now->tm_min << ":" << now->tm_sec << "]";
    ss << " ";
    ss << logMessage;

    if (mIsCerr)
    {
        std::cerr << ss.str() << std::endl;
    }
    else
    {
        std::cout << ss.str() << std::endl;
    }
}

void Logger::logEmptyString(const LogLevel logLevel)
{
    const std::string logLevelString = getLogLevelString(logLevel);
    const std::string color = getLogLevelColor(logLevel);

    if (mIsFileLogging && (mLogLevel & logLevel))
    {
        if (!logFile.is_open())
        {
            Logger::log(ERROR, "Failed log to file, logging on console only");
            mIsFileLogging = false;
            return;
        }
        logFile << "[" << logLevelString << "] ";
    }

    if (mIsConsoleLogging && (mLogLevel & logLevel))
    {
        const std::string logLevelString = getLogLevelString(logLevel);

        if (mIsCerr)
            std::cerr << color << "[" <<  logLevelString << "]"<< ANSI_RESET << " ";
        else
            std::cout << color << "[" <<  logLevelString << "]" << ANSI_RESET << " " ;
    }
}

const std::string& Logger::getLogLevelString(const LogLevel logLevel)
{
    switch (logLevel)
    {
    case INFO:
        return Logger::mLogLevelString = "INFO";
    case WARNING:
        return Logger::mLogLevelString = "WARNING";
    case DEBUG:
        return Logger::mLogLevelString = "DEBUG";
    case ERROR:
        return Logger::mLogLevelString = "ERROR";
    case FATAL:
        return Logger::mLogLevelString = "FATAL";
    case SEND:
        return Logger::mLogLevelString = "SEND";
    case RECV:
        return Logger::mLogLevelString = "RECV";
    default:
        return Logger::mLogLevelString = "";
    }
}

const std::string& Logger::getLogLevelColor(const LogLevel logLevel)
{
    switch (logLevel)
    {
    case INFO:
        return Logger::mLogColor = ANSI_GREEN;
    case WARNING:
        return Logger::mLogColor = ANSI_YELLOW;
    case DEBUG:
        return Logger::mLogColor = ANSI_CYAN;
    case ERROR:
        return Logger::mLogColor = ANSI_RED;
    case FATAL:
        return Logger::mLogColor = ANSI_BRED;
    case SEND:
        return Logger::mLogColor = ANSI_BWBBLUE;
    case RECV:
        return Logger::mLogColor = ANSI_BWBMAGENTA;
    default:
        return Logger::mLogColor = "";
    }
}

Logger::Logger() {}
Logger::~Logger() {}