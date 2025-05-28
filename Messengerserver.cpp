#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include <map>
#include <mutex>
#include <sstream>
#include <fstream>   // Для работы с файлами
#include <algorithm> // Для std::transform, std::remove
#include <chrono>    // Для std::chrono
#include <iomanip>   // Для std::put_time, std::get_time
#include <filesystem>// Для std::filesystem (C++17)
#include <cctype>    // для ::toupper

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h> 
#include <string.h> 
#include <sys/stat.h> // Для mkdir в Unix, если filesystem не используется
#endif

// Кросс-платформенные определения
#ifdef _WIN32
typedef SOCKET SocketType;
#define INVALID_SOCKET_VALUE INVALID_SOCKET
#define SOCKET_ERROR_VALUE SOCKET_ERROR
#define CLOSE_SOCKET closesocket
#define GET_LAST_ERROR WSAGetLastError()
#define GET_LAST_ERROR_STR std::to_string(WSAGetLastError())
#else
typedef int SocketType;
#define INVALID_SOCKET_VALUE -1
#define SOCKET_ERROR_VALUE -1
#define CLOSE_SOCKET close
#define GET_LAST_ERROR errno
#define GET_LAST_ERROR_STR strerror(errno)
#endif

// Глобальные переменные
std::map<std::string, SocketType> G_connectedUsers;
std::mutex G_usersMutex;

std::map<std::string, std::string> G_usersCredentials;
std::mutex G_credentialsMutex;
const std::string G_credentialsFileName = "users.txt";
const std::string G_chatLogsDir = "chat_logs/";


// --- Логирование ---
std::mutex G_logMutex;
#define LOG_MSG(socket, msg) \
    do { \
        std::lock_guard<std::mutex> lock(G_logMutex); \
        std::cout << "[" << std::this_thread::get_id() << "] Socket " << socket << ": " << msg << std::endl; \
    } while(0)

#define LOG_SERVER_MSG(msg) \
    do { \
        std::lock_guard<std::mutex> lock(G_logMutex); \
        std::cout << "[" << std::this_thread::get_id() << "] SERVER: " << msg << std::endl; \
    } while(0)


void logConnectedUsersInternal() {
    std::cout << "Connected users: ";
    if (G_connectedUsers.empty()) {
        std::cout << "None";
    }
    else {
        for (const auto& user : G_connectedUsers) {
            std::cout << user.first << "(" << user.second << ") ";
        }
    }
    std::cout << "\n";
}

void logConnectedUsers() {
    std::lock_guard<std::mutex> lock(G_usersMutex);
    std::lock_guard<std::mutex> log_lock(G_logMutex);
    logConnectedUsersInternal();
}

void ensureDirectoryExists(const std::string& path) {
    if (!std::filesystem::exists(path)) {
        try {
            if (std::filesystem::create_directory(path)) {
                LOG_SERVER_MSG("Created directory: " + path);
            }
            else {
                LOG_SERVER_MSG("Failed to create directory (unknown reason): " + path);
            }
        }
        catch (const std::filesystem::filesystem_error& e) {
            LOG_SERVER_MSG("Error creating directory '" + path + "': " + std::string(e.what()));
        }
    }
}

bool loadCredentialsFromFile() {
    std::ifstream inFile(G_credentialsFileName);
    if (!inFile.is_open()) {
        LOG_SERVER_MSG("Credentials file '" + G_credentialsFileName + "' not found. Will be created on first registration.");
        return true;
    }

    LOG_SERVER_MSG("Loading credentials from '" + G_credentialsFileName + "'...");
    G_usersCredentials.clear();
    std::string line;
    int count = 0;
    while (std::getline(inFile, line)) {
        std::istringstream iss(line);
        std::string username, password;
        if (std::getline(iss, username, ':') && std::getline(iss, password)) {
            if (!password.empty() && password.back() == '\r') {
                password.pop_back();
            }
            G_usersCredentials[username] = password;
            count++;
        }
        else {
            LOG_SERVER_MSG("Malformed line in credentials file: " + line);
        }
    }
    inFile.close();
    LOG_SERVER_MSG("Loaded " + std::to_string(count) + " user(s) from credentials file.");
    return true;
}

bool initUserStore() {
    std::lock_guard<std::mutex> lock(G_credentialsMutex);
    LOG_SERVER_MSG("User store initializing (file-based).");
    ensureDirectoryExists(G_chatLogsDir);
    return loadCredentialsFromFile();
}

void shutdownUserStore() {
    LOG_SERVER_MSG("User store (file-based) shut down.");
}

std::string serverReadLine(SocketType socket) {
    std::string line;
    char ch;
    while (true) {
        int bytesReceived = recv(socket, &ch, 1, 0);
        if (bytesReceived == 0) {
            LOG_MSG(socket, "Client disconnected gracefully.");
            return "";
        }
        if (bytesReceived < 0) {
            int error_code = GET_LAST_ERROR;
            std::string error_str = GET_LAST_ERROR_STR;
            LOG_MSG(socket, "recv failed with error: " + std::to_string(error_code) + " (" + error_str + ")");
            return "";
        }
        if (ch == '\n') {
            break;
        }
        if (ch != '\r') {
            line += ch;
        }
    }
    LOG_MSG(socket, "Received: \"" + line + "\"");
    return line;
}

void serverSendMessage(SocketType socket, const std::string& message) {
    std::string msg = message + "\n";
    int msg_len = static_cast<int>(msg.length());
    int bytesSent = send(socket, msg.c_str(), msg_len, 0);

    if (bytesSent == SOCKET_ERROR_VALUE) {
        LOG_MSG(socket, "Send failed with error: " + std::string(GET_LAST_ERROR_STR) + " for message: \"" + message + "\"");
    }
    else if (bytesSent < msg_len) {
        LOG_MSG(socket, "Send sent only " + std::to_string(bytesSent) + "/" + std::to_string(msg_len) + " bytes for message: \"" + message + "\"");
    }
    else {
        LOG_MSG(socket, "Sent: \"" + message + "\" (" + std::to_string(bytesSent) + " bytes)");
    }
}

bool userExists(SocketType s, const std::string& username) {
    LOG_MSG(s, "userExists: Checking for user '" + username + "' in memory map.");
    std::lock_guard<std::mutex> lock(G_credentialsMutex);
    // LOG_MSG(s, "userExists: Acquired G_credentialsMutex for '" + username + "'"); // Слишком много логов, убрал
    bool exists = G_usersCredentials.count(username) > 0;
    // LOG_MSG(s, "userExists: User '" + username + (exists ? "' exists." : "' does not exist.") + " Releasing G_credentialsMutex."); // Слишком много логов
    return exists;
}

bool verifyUser(SocketType s, const std::string& username, const std::string& password) {
    LOG_MSG(s, "verifyUser: Verifying user '" + username + "' from memory map.");
    std::lock_guard<std::mutex> lock(G_credentialsMutex);
    // LOG_MSG(s, "verifyUser: Acquired G_credentialsMutex for '" + username + "'");
    auto it = G_usersCredentials.find(username);
    bool ok = false;
    if (it != G_usersCredentials.end()) {
        ok = (it->second == password);
    }
    // LOG_MSG(s, "verifyUser: User '" + username + (ok ? "' verified." : "' verification failed.") + " Releasing G_credentialsMutex.");
    return ok;
}

bool insertUser(SocketType s, const std::string& username, const std::string& password) {
    LOG_MSG(s, "insertUser: Attempting to insert user '" + username + "'");
    std::lock_guard<std::mutex> lock(G_credentialsMutex);
    LOG_MSG(s, "insertUser: Acquired G_credentialsMutex for '" + username + "'");

    if (G_usersCredentials.count(username)) {
        LOG_MSG(s, "insertUser: User '" + username + "' already exists in memory map. Insertion failed. Releasing G_credentialsMutex.");
        return false;
    }

    std::ofstream outFile(G_credentialsFileName, std::ios::app);
    if (!outFile.is_open()) {
        LOG_MSG(s, "insertUser: CRITICAL - Failed to open credentials file '" + G_credentialsFileName + "' for writing! Releasing G_credentialsMutex.");
        return false;
    }

    outFile << username << ":" << password << std::endl;
    if (!outFile.good()) {
        LOG_MSG(s, "insertUser: CRITICAL - Failed to write to credentials file '" + G_credentialsFileName + "'! Releasing G_credentialsMutex.");
        outFile.close();
        return false;
    }
    outFile.close();
    LOG_MSG(s, "insertUser: User '" + username + "' successfully written to file '" + G_credentialsFileName + "'.");

    G_usersCredentials[username] = password;
    LOG_MSG(s, "insertUser: User '" + username + "' inserted into memory map. Map size: " + std::to_string(G_usersCredentials.size()) + ". Releasing G_credentialsMutex.");
    return true;
}

std::string getChatFilename(const std::string& user1, const std::string& user2) {
    if (user1 < user2) {
        return G_chatLogsDir + "chat_" + user1 + "_" + user2 + ".txt";
    }
    else {
        return G_chatLogsDir + "chat_" + user2 + "_" + user1 + ".txt";
    }
}

std::string getCurrentTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&in_time_t), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}


void handleClient(SocketType clientSocket) {
    LOG_MSG(clientSocket, "New client handler started.");
    std::string currentUsername;
    bool loggedIn = false;

    try {
        while (true) {
            std::string command_line = serverReadLine(clientSocket);
            if (command_line.empty()) {
                break;
            }

            std::istringstream iss(command_line);
            std::string cmd_token_from_client;
            iss >> cmd_token_from_client;

            std::string cmd_token_upper = cmd_token_from_client;
            std::transform(cmd_token_upper.begin(), cmd_token_upper.end(), cmd_token_upper.begin(),
                [](unsigned char c) { return std::toupper(c); });
            LOG_MSG(clientSocket, "Parsed command token (UPPER): '" + cmd_token_upper + "' from original: '" + cmd_token_from_client + "'");


            if (!loggedIn) {
                if (cmd_token_upper == "LOGIN") {
                    std::string tempUsername, password;
                    iss >> tempUsername >> password;
                    LOG_MSG(clientSocket, "LOGIN attempt: User='" + tempUsername + "', Pass='***'"); // Пароль не логируем
                    if (!tempUsername.empty() && !password.empty()) {
                        if (verifyUser(clientSocket, tempUsername, password)) {
                            LOG_MSG(clientSocket, "LOGIN: verifyUser successful for '" + tempUsername + "'. Acquiring G_usersMutex.");
                            std::lock_guard<std::mutex> lock(G_usersMutex);
                            LOG_MSG(clientSocket, "LOGIN: Acquired G_usersMutex for '" + tempUsername + "'. Checking if connected.");
                            if (G_connectedUsers.find(tempUsername) == G_connectedUsers.end()) {
                                G_connectedUsers[tempUsername] = clientSocket;
                                currentUsername = tempUsername;
                                loggedIn = true;
                                LOG_MSG(clientSocket, "User '" + currentUsername + "' logged in.");
                                { std::lock_guard<std::mutex> log_lock(G_logMutex); logConnectedUsersInternal(); }
                                serverSendMessage(clientSocket, "OK_LOGIN Welcome, " + currentUsername + "!");
                            }
                            else {
                                LOG_MSG(clientSocket, "LOGIN: User '" + tempUsername + "' already logged in elsewhere.");
                                serverSendMessage(clientSocket, "ERROR_LOGIN User already logged in elsewhere.");
                            }
                            // LOG_MSG(clientSocket, "LOGIN: Releasing G_usersMutex for '" + tempUsername + "'."); // RAII сделает это
                        }
                        else {
                            LOG_MSG(clientSocket, "LOGIN: Invalid username or password for '" + tempUsername + "'.");
                            serverSendMessage(clientSocket, "ERROR_LOGIN Invalid username or password.");
                        }
                    }
                    else {
                        LOG_MSG(clientSocket, "LOGIN: Invalid format.");
                        serverSendMessage(clientSocket, "ERROR_CMD Invalid login format. Usage: LOGIN <username> <password>");
                    }
                }
                else if (cmd_token_upper == "REGISTRATION") {
                    std::string tempUsername, password;
                    iss >> tempUsername >> password;
                    LOG_MSG(clientSocket, "REGISTRATION attempt: User='" + tempUsername + "', Pass='***'");
                    if (!tempUsername.empty() && !password.empty()) {
                        LOG_MSG(clientSocket, "REGISTRATION: Calling userExists for '" + tempUsername + "'.");
                        if (!userExists(clientSocket, tempUsername)) {
                            LOG_MSG(clientSocket, "REGISTRATION: User '" + tempUsername + "' does not exist. Calling insertUser.");
                            if (insertUser(clientSocket, tempUsername, password)) {
                                LOG_MSG(clientSocket, "REGISTRATION: insertUser successful for '" + tempUsername + "'. Acquiring G_usersMutex for auto-login.");
                                std::lock_guard<std::mutex> lock(G_usersMutex);
                                LOG_MSG(clientSocket, "REGISTRATION: Acquired G_usersMutex for '" + tempUsername + "'.");
                                G_connectedUsers[tempUsername] = clientSocket;
                                currentUsername = tempUsername;
                                loggedIn = true;
                                LOG_MSG(clientSocket, "User '" + currentUsername + "' registered and logged in.");
                                { std::lock_guard<std::mutex> log_lock(G_logMutex); logConnectedUsersInternal(); }
                                serverSendMessage(clientSocket, "OK_REGISTERED Welcome, " + currentUsername + "!");
                                // LOG_MSG(clientSocket, "REGISTRATION: Releasing G_usersMutex for '" + tempUsername + "'.");
                            }
                            else {
                                LOG_MSG(clientSocket, "REGISTRATION: insertUser failed for '" + tempUsername + "'.");
                                serverSendMessage(clientSocket, "ERROR_REGISTRATION Registration failed (server error).");
                            }
                        }
                        else {
                            LOG_MSG(clientSocket, "REGISTRATION: User '" + tempUsername + "' already exists.");
                            serverSendMessage(clientSocket, "ERROR_REGISTRATION User already exists.");
                        }
                    }
                    else {
                        LOG_MSG(clientSocket, "REGISTRATION: Invalid format.");
                        serverSendMessage(clientSocket, "ERROR_CMD Invalid registration format. Usage: REGISTRATION <username> <password>");
                    }
                }
                else {
                    std::string rest_of_command;
                    std::getline(iss, rest_of_command); // Считать остаток, чтобы лог был полным
                    LOG_MSG(clientSocket, "Command '" + cmd_token_from_client + rest_of_command + "' received before login/registration.");
                    serverSendMessage(clientSocket, "ERROR_AUTH Please login or register. Commands: LOGIN, REGISTRATION, HELP, EXIT");
                }
            }
            else { // User is loggedIn
                if (cmd_token_upper == "SEND_PRIVATE") {
                    std::string recipient_from_stream;
                    iss >> recipient_from_stream;
                    iss >> std::ws;
                    std::string message_content_from_stream;
                    std::getline(iss, message_content_from_stream);

                    LOG_MSG(clientSocket, "SEND_PRIVATE Raw Parse: Recipient='" + recipient_from_stream + "', MessageContentRaw='" + message_content_from_stream + "'");

                    std::string recipient = recipient_from_stream;
                    std::string message_content = message_content_from_stream;

                    LOG_MSG(clientSocket, "SEND_PRIVATE Final Check: Recipient='" + recipient + "', MessageContent='" + message_content + "'");

                    if (recipient.empty() || message_content.empty()) {
                        LOG_MSG(clientSocket, "SEND_PRIVATE: Invalid format - recipient or message is empty.");
                        serverSendMessage(clientSocket, "ERROR_CMD Invalid SEND_PRIVATE. Usage: SEND_PRIVATE <recipient> <message>");
                    }
                    else if (recipient == currentUsername) {
                        LOG_MSG(clientSocket, "SEND_PRIVATE: User trying to send message to themselves.");
                        serverSendMessage(clientSocket, "ERROR_SEND Cannot send message to yourself.");
                    }
                    else {
                        LOG_MSG(clientSocket, "SEND_PRIVATE: Calling userExists for recipient '" + recipient + "'.");
                        if (!userExists(clientSocket, recipient)) {
                            LOG_MSG(clientSocket, "SEND_PRIVATE: Recipient '" + recipient + "' does not exist.");
                            serverSendMessage(clientSocket, "ERROR_SEND Recipient '" + recipient + "' does not exist.");
                        }
                        else {
                            std::string chatFile = getChatFilename(currentUsername, recipient);
                            std::string timestamp = getCurrentTimestamp();
                            std::string formatted_log_message = timestamp + ":" + currentUsername + ":" + message_content;

                            std::ofstream chat_log_file(chatFile, std::ios::app);
                            if (chat_log_file.is_open()) {
                                chat_log_file << formatted_log_message << std::endl;
                                chat_log_file.close();
                                LOG_MSG(clientSocket, "SEND_PRIVATE: Message saved to chat log: " + chatFile);

                                SocketType recipientSocket = INVALID_SOCKET_VALUE;
                                {
                                    std::lock_guard<std::mutex> lock(G_usersMutex);
                                    auto it = G_connectedUsers.find(recipient);
                                    if (it != G_connectedUsers.end()) {
                                        recipientSocket = it->second;
                                    }
                                }

                                if (recipientSocket != INVALID_SOCKET_VALUE) {
                                    std::string fullMessage_to_recipient = "MSG_FROM " + currentUsername + ": " + message_content;
                                    serverSendMessage(recipientSocket, fullMessage_to_recipient);
                                    LOG_MSG(clientSocket, "SEND_PRIVATE: Message delivered online to '" + recipient + "'.");
                                }
                                else {
                                    LOG_MSG(clientSocket, "SEND_PRIVATE: Recipient '" + recipient + "' is offline. Message saved.");
                                }
                                serverSendMessage(clientSocket, "OK_SENT Message to " + recipient + " processed.");

                            }
                            else {
                                LOG_MSG(clientSocket, "SEND_PRIVATE: CRITICAL - Failed to open chat log file '" + chatFile + "' for writing!");
                                serverSendMessage(clientSocket, "ERROR_SEND Server error, message not saved.");
                            }
                        }
                    }
                }
                else if (cmd_token_upper == "GET_HISTORY") {
                    std::string otherUsername;
                    iss >> otherUsername;
                    LOG_MSG(clientSocket, "GET_HISTORY request for chat with '" + otherUsername + "' from user '" + currentUsername + "'.");

                    if (otherUsername.empty()) {
                        serverSendMessage(clientSocket, "ERROR_CMD Invalid GET_HISTORY format. Usage: GET_HISTORY <username>");
                    }
                    else if (otherUsername == currentUsername) {
                        serverSendMessage(clientSocket, "NO_HISTORY You cannot request history with yourself in this manner."); // Или ERROR_CMD
                    }
                    else if (!userExists(clientSocket, otherUsername)) {
                        serverSendMessage(clientSocket, "ERROR_CMD User '" + otherUsername + "' does not exist for history request.");
                    }
                    else {
                        std::string chatFile = getChatFilename(currentUsername, otherUsername);
                        std::ifstream historyFile(chatFile);

                        if (historyFile.is_open()) {
                            serverSendMessage(clientSocket, "HISTORY_START " + otherUsername);
                            LOG_MSG(clientSocket, "Sending history for chat with '" + otherUsername + "' to '" + currentUsername + "'.");
                            std::string history_line;
                            int line_count = 0;
                            while (std::getline(historyFile, history_line)) {
                                serverSendMessage(clientSocket, "HIST_MSG " + history_line);
                                line_count++;
                            }
                            historyFile.close();
                            serverSendMessage(clientSocket, "HISTORY_END " + otherUsername);
                            LOG_MSG(clientSocket, "Finished sending " + std::to_string(line_count) + " history lines for chat with '" + otherUsername + "'.");
                        }
                        else {
                            LOG_MSG(clientSocket, "No history file found for chat between '" + currentUsername + "' and '" + otherUsername + "'. File: " + chatFile);
                            serverSendMessage(clientSocket, "NO_HISTORY " + otherUsername);
                        }
                    }
                }
                else if (cmd_token_upper == "LOGOUT") {
                    LOG_MSG(clientSocket, "LOGOUT command received for user '" + currentUsername + "'.");
                    serverSendMessage(clientSocket, "OK_LOGOUT Goodbye, " + currentUsername + "!");
                    loggedIn = false;
                    // Не удаляем из G_connectedUsers здесь, это произойдет при закрытии сокета или в cleanup ниже
                    break; // Завершаем цикл обработки команд для этого клиента
                }
                else {
                    std::string rest_of_command;
                    std::getline(iss, rest_of_command);
                    LOG_MSG(clientSocket, "Invalid command '" + cmd_token_from_client + rest_of_command + "' received while logged in.");
                    serverSendMessage(clientSocket, "ERROR_CMD Invalid command. Available: SEND_PRIVATE, GET_HISTORY, HELP, EXIT (acts as LOGOUT)");
                }
            }
            LOG_MSG(clientSocket, "End of command processing loop iteration.");
        }
    }
    catch (const std::exception& e) {
        LOG_MSG(clientSocket, "Exception in handleClient for user '" + (currentUsername.empty() ? "[unidentified]" : currentUsername) + "': " + e.what());
    }
    catch (...) {
        LOG_MSG(clientSocket, "Unknown exception in handleClient for user '" + (currentUsername.empty() ? "[unidentified]" : currentUsername) + "'");
    }

    if (!currentUsername.empty()) {
        LOG_MSG(clientSocket, "Cleaning up connection for user '" + currentUsername + "'. Acquiring G_usersMutex.");
        std::lock_guard<std::mutex> lock(G_usersMutex);
        // LOG_MSG(clientSocket, "Acquired G_usersMutex for cleanup of '" + currentUsername + "'.");
        auto it = G_connectedUsers.find(currentUsername);
        if (it != G_connectedUsers.end() && it->second == clientSocket) { // Важно! Удаляем только если сокет совпадает
            G_connectedUsers.erase(it);
            LOG_MSG(clientSocket, "User '" + currentUsername + "' connection data cleaned up from G_connectedUsers.");
            { std::lock_guard<std::mutex> log_lock(G_logMutex); logConnectedUsersInternal(); }
        }
        else {
            // LOG_MSG(clientSocket, "User '" + currentUsername + "' not found in connected users or socket mismatch during cleanup.");
        }
        // LOG_MSG(clientSocket, "Releasing G_usersMutex for cleanup of '" + currentUsername + "'.");
    }
    LOG_MSG(clientSocket, "Closing connection.");
    CLOSE_SOCKET(clientSocket);
    LOG_MSG(clientSocket, "Client handler finished.");
}

int main() {
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        LOG_SERVER_MSG("WSAStartup failed.");
        return 1;
    }
#endif

    if (!initUserStore()) {
        LOG_SERVER_MSG("Failed to initialize user store. Exiting.");
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }

    SocketType serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == INVALID_SOCKET_VALUE) {
        LOG_SERVER_MSG("Socket creation failed: " + std::string(GET_LAST_ERROR_STR));
        shutdownUserStore();
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }

    int opt = 1;
#ifdef _WIN32
    if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt)) == SOCKET_ERROR_VALUE) {
        LOG_SERVER_MSG("setsockopt(SO_REUSEADDR) failed: " + std::string(GET_LAST_ERROR_STR));
    }
#else
    if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == SOCKET_ERROR_VALUE) {
        LOG_SERVER_MSG("setsockopt(SO_REUSEADDR) failed: " + std::string(GET_LAST_ERROR_STR));
    }
#endif


    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(8081);

    if (bind(serverSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR_VALUE) {
        LOG_SERVER_MSG("Bind failed: " + std::string(GET_LAST_ERROR_STR));
        CLOSE_SOCKET(serverSocket);
        shutdownUserStore();
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }

    if (listen(serverSocket, SOMAXCONN) == SOCKET_ERROR_VALUE) {
        LOG_SERVER_MSG("Listen failed: " + std::string(GET_LAST_ERROR_STR));
        CLOSE_SOCKET(serverSocket);
        shutdownUserStore();
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }

    LOG_SERVER_MSG("Server listening on port 8081 (using file-based user store)...");

    while (true) {
        sockaddr_in clientAddr;
#ifdef _WIN32
        int addrLen = sizeof(clientAddr);
#else
        socklen_t addrLen = sizeof(clientAddr);
#endif
        SocketType clientSocket = accept(serverSocket, (sockaddr*)&clientAddr, &addrLen);

        if (clientSocket == INVALID_SOCKET_VALUE) {
            int error_code = GET_LAST_ERROR;
            std::string error_str = GET_LAST_ERROR_STR;
#ifdef _WIN32
            if (error_code == WSAEINTR || error_code == WSAENOTSOCK) {
                LOG_SERVER_MSG("accept interrupted (WSAEINTR/WSAENOTSOCK), server likely shutting down.");
                break;
            }
#else
            if (error_code == EINTR || error_code == EBADF) {
                LOG_SERVER_MSG("accept interrupted (EINTR/EBADF), server likely shutting down.");
                break;
            }
#endif
            LOG_SERVER_MSG("Accept failed with error: " + std::to_string(error_code) + "(" + error_str + "). Continuing...");
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }

        char clientIpStr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &clientAddr.sin_addr, clientIpStr, INET_ADDRSTRLEN);
        LOG_SERVER_MSG(std::string("Client accepted from ") + clientIpStr + ":" + std::to_string(ntohs(clientAddr.sin_port)) +
            " assigned to socket " + std::to_string(clientSocket));

        try {
            std::thread clientThread(handleClient, clientSocket);
            clientThread.detach();
        }
        catch (const std::system_error& e) {
            LOG_SERVER_MSG(std::string("Failed to create thread for socket ") + std::to_string(clientSocket) + ": " + e.what() + " (Code: " + std::to_string(e.code().value()) + ")");
            CLOSE_SOCKET(clientSocket);
        }
        catch (const std::exception& e) {
            LOG_SERVER_MSG(std::string("Failed to create thread (std::exception) for socket ") + std::to_string(clientSocket) + ": " + e.what());
            CLOSE_SOCKET(clientSocket);
        }
    }

    LOG_SERVER_MSG("Server shutting down.");
    CLOSE_SOCKET(serverSocket);
    shutdownUserStore();
#ifdef _WIN32
    WSACleanup();
#endif
    LOG_SERVER_MSG("Server has shut down.");
    return 0;
}