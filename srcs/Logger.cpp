#include "Logger.hpp" 

bool             Logger::mIsFileLogging;
bool             Logger::mIsConsoleLogging;
bool             Logger::mIsCerr;
std::string      Logger::mFileName;
std::ofstream    Logger::logFile;

void Logger::setFileLogging(const std::string& fileName)
{
    mIsFileLogging = true;
    mFileName = fileName;
    logFile.open(mFileName, std::ios::out | std::ios::app);
    if (logFile.fail())
    {
        Logger::log(ERROR, "Failed to open log file, logging on console only");
        mIsFileLogging = false;
        assert(false);
    }
}

void Logger::setConsoleLogging(bool isConsoleLogging)
{
    mIsConsoleLogging = isConsoleLogging;
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

void Logger::log(LogLevel logLevel, const std::string& logMessage)
{
    if (logMessage.empty())
    {
        logEmptyString(logLevel);
        return;
    }

    std::string logLevelString;
    switch (logLevel)
    {
    case INFO:
        logLevelString = "INFO";
        break;
    case WARNING:
        logLevelString = "WARNING";
        break;
    case DEBUG:
        logLevelString = "DEBUG";
        break;
    case ERROR:
        logLevelString = "ERROR";
        mIsCerr = true;
        break;
    case FATAL:
        logLevelString = "FATAL";
        mIsCerr = true;
        break;
    default:
        logLevelString = "UNKNOWN";
        break;
    }

    std::time_t currentTime = std::time(0);
    std::tm* now = std::localtime(&currentTime);
    std::stringstream ss;

    // [2021-01-01 12:00:00]
    ss << "[" << now->tm_year + 1900 << "-" << now->tm_mon + 1 << "-" << now->tm_mday << " " << now->tm_hour << ":" << now->tm_min << ":" << now->tm_sec << "] ";

    std::string timeString = ss.str();

    // [2021-01-01 12:00:00] INFO : logMessage
    switch (logLevel)
    {
    case INFO:
        ss << ANSI_GREEN << timeString << logLevelString << " : " << logMessage << ANSI_RESET;
        break;
    case WARNING:
        ss << ANSI_YELLOW << timeString << logLevelString << " : " << logMessage << ANSI_RESET;
        break;
    case ERROR:
        ss << ANSI_RED << timeString << logLevelString << " : " << logMessage << ANSI_RESET;
        break;
    case DEBUG:
        ss << ANSI_CYAN << timeString << logLevelString << " : " << logMessage << ANSI_RESET;
        break;
    case FATAL:
        ss << ANSI_BRED << timeString << logLevelString << " : " << logMessage << ANSI_RESET;
        break;
    default:
        ss << timeString << " : " << logMessage;
        break;
    }

    std::string logString = ss.str();

    if (mIsFileLogging)
        logToFile(logString);

    if (mIsConsoleLogging)
        logToConsole(logString, mIsCerr);
}

void Logger::logToFile(const std::string& logMessage)
{
    if (!logFile.is_open())
    {
        Logger::log(ERROR, "Failed log to file, logging on console only");
        return;
    }
    logFile << logMessage << std::endl;
}

void Logger::logToConsole(const std::string& logMessage, bool isCerr)
{
    if (isCerr)
    {
        std::cerr << logMessage << std::endl;
    }
    else
    {
        std::cout << logMessage << std::endl;
    }
}

void Logger::logEmptyString(LogLevel logLevel)
{
    std::string logLevelString;
    std::string color;
    switch (logLevel)
    {
    case INFO:
        color = ANSI_GREEN;
        logLevelString = "INFO";
        break;
    case WARNING:
        color = ANSI_YELLOW;
        logLevelString = "WARNING";
        break;
    case DEBUG:
        color = ANSI_CYAN;
        logLevelString = "DEBUG";
        break;
    case ERROR:
        color = ANSI_RED;
        logLevelString = "ERROR";
        mIsCerr = true;
        break;
    case FATAL:
        color = ANSI_BRED;
        logLevelString = "FATAL";
        mIsCerr = true;
        break;
    default:
        logLevelString = "UNKNOWN";
        break;
    }
    logLevelString = color + "[" + logLevelString + "]" + ANSI_RESET + " ";

    if (mIsConsoleLogging)
    {
        if (mIsCerr)
            std::cerr << logLevelString;
        else
            std::cout << logLevelString;
    }
    if (mIsFileLogging)
    {
        if (!logFile.is_open())
        {
            Logger::log(ERROR, "Failed log to file, logging on console only");
            Logger::mIsFileLogging = false;
            return;
        }
        logFile << logLevelString;
    }
}


Logger::Logger(){}
Logger::~Logger(){}