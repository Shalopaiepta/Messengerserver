#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include <map>
#include <mutex>
#include <sstream>
#include <fstream>
#include <algorithm>
#include <chrono>
#include <iomanip>
#include <filesystem> // Для std::filesystem (C++17)
#include <cctype>    // для ::toupper
#include <set>       // Для std::set в GET_CHAT_PARTNERS

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
#include <sys/stat.h>
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
    // G_credentialsMutex будет взят в initUserStore
    G_usersCredentials.clear();
    std::string line;
    int count = 0;
    while (std::getline(inFile, line)) {
        std::istringstream iss(line);
        std::string username, password;
        if (std::getline(iss, username, ':') && std::getline(iss, password)) {
            if (!username.empty() && username.back() == '\r') username.pop_back();
            if (!password.empty() && password.back() == '\r') password.pop_back();

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
            LOG_MSG(socket, "Client disconnected gracefully during read.");
            return "";
        }
        if (bytesReceived < 0) {
            int error_code = GET_LAST_ERROR;
            std::string error_str = GET_LAST_ERROR_STR;
#ifdef _WIN32
            if (error_code == WSAECONNRESET || error_code == WSAESHUTDOWN || error_code == WSAETIMEDOUT) {
                LOG_MSG(socket, "recv failed with graceful disconnect or timeout: " + std::to_string(error_code) + " (" + error_str + ")");
            }
            else {
                LOG_MSG(socket, "recv failed with error: " + std::to_string(error_code) + " (" + error_str + ")");
            }
#else
            if (error_code == ECONNRESET || error_code == EPIPE || error_code == ETIMEDOUT) {
                LOG_MSG(socket, "recv failed with graceful disconnect or timeout: " + std::to_string(error_code) + " (" + error_str + ")");
            }
            else {
                LOG_MSG(socket, "recv failed with error: " + std::to_string(error_code) + " (" + error_str + ")");
            }
#endif
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
    int bytesSentTotal = 0;
    while (bytesSentTotal < msg_len) {
        int bytesSent = send(socket, msg.c_str() + bytesSentTotal, msg_len - bytesSentTotal, 0);
        if (bytesSent == SOCKET_ERROR_VALUE) {
            LOG_MSG(socket, "Send failed with error: " + std::string(GET_LAST_ERROR_STR) + " for message: \"" + message + "\"");
            return;
        }
        bytesSentTotal += bytesSent;
    }
    LOG_MSG(socket, "Sent: \"" + message + "\" (" + std::to_string(bytesSentTotal) + " bytes)");
}

bool userExists(SocketType s, const std::string& username) {
    std::lock_guard<std::mutex> lock(G_credentialsMutex);
    return G_usersCredentials.count(username) > 0;
}

bool verifyUser(SocketType s, const std::string& username, const std::string& password) {
    std::lock_guard<std::mutex> lock(G_credentialsMutex);
    auto it = G_usersCredentials.find(username);
    if (it != G_usersCredentials.end()) {
        return (it->second == password);
    }
    return false;
}

bool insertUser(SocketType s, const std::string& username, const std::string& password) {
    std::lock_guard<std::mutex> lock(G_credentialsMutex);
    if (G_usersCredentials.count(username)) {
        return false;
    }

    std::ofstream outFile(G_credentialsFileName, std::ios::app);
    if (!outFile.is_open()) {
        LOG_SERVER_MSG("CRITICAL - Failed to open credentials file '" + G_credentialsFileName + "' for writing!");
        return false;
    }
    outFile << username << ":" << password << std::endl;
    if (!outFile.good()) {
        LOG_SERVER_MSG("CRITICAL - Failed to write to credentials file '" + G_credentialsFileName + "'!");
        outFile.close();
        return false;
    }
    outFile.close();
    G_usersCredentials[username] = password;
    LOG_SERVER_MSG("User '" + username + "' successfully registered.");
    return true;
}

std::string getChatFilename(const std::string& user1, const std::string& user2) {
    if (user1 < user2) {
        return G_chatLogsDir + "chat_" + user1 + "_" + user2 + ".txt";
    }
    return G_chatLogsDir + "chat_" + user2 + "_" + user1 + ".txt";
}

std::string getCurrentTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);
    std::tm buf;
#ifdef _WIN32
    localtime_s(&buf, &in_time_t);
#else
    localtime_r(&in_time_t, &buf);
#endif
    std::stringstream ss;
    ss << std::put_time(&buf, "%Y-%m-%d %H:%M:%S");
    return ss.str();
}


void handleClient(SocketType clientSocket) {
    LOG_MSG(clientSocket, "New client handler started.");
    std::string currentUsername_local;
    bool loggedIn_local = false;

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

            LOG_MSG(clientSocket, "Parsed command: '" + cmd_token_upper + "'");

            if (!loggedIn_local) {
                if (cmd_token_upper == "LOGIN") {
                    std::string tempUsername, password;
                    iss >> tempUsername >> password;
                    if (!tempUsername.empty() && !password.empty()) {
                        if (verifyUser(clientSocket, tempUsername, password)) {
                            std::lock_guard<std::mutex> lock(G_usersMutex);
                            if (G_connectedUsers.find(tempUsername) == G_connectedUsers.end()) {
                                G_connectedUsers[tempUsername] = clientSocket;
                                currentUsername_local = tempUsername;
                                loggedIn_local = true;
                                LOG_MSG(clientSocket, "User '" + currentUsername_local + "' logged in.");
                                { std::lock_guard<std::mutex> log_lock(G_logMutex); logConnectedUsersInternal(); }
                                serverSendMessage(clientSocket, "OK_LOGIN Welcome, " + currentUsername_local + "!");
                            }
                            else {
                                serverSendMessage(clientSocket, "ERROR_LOGIN User '" + tempUsername + "' already logged in elsewhere.");
                            }
                        }
                        else {
                            serverSendMessage(clientSocket, "ERROR_LOGIN Invalid username or password.");
                        }
                    }
                    else {
                        serverSendMessage(clientSocket, "ERROR_CMD Invalid login format.");
                    }
                }
                else if (cmd_token_upper == "REGISTRATION") {
                    std::string tempUsername, password;
                    iss >> tempUsername >> password;
                    if (!tempUsername.empty() && !password.empty()) {
                        if (!userExists(clientSocket, tempUsername)) {
                            if (insertUser(clientSocket, tempUsername, password)) {
                                std::lock_guard<std::mutex> lock(G_usersMutex);
                                G_connectedUsers[tempUsername] = clientSocket;
                                currentUsername_local = tempUsername;
                                loggedIn_local = true;
                                LOG_MSG(clientSocket, "User '" + currentUsername_local + "' registered and logged in.");
                                { std::lock_guard<std::mutex> log_lock(G_logMutex); logConnectedUsersInternal(); }
                                serverSendMessage(clientSocket, "OK_REGISTERED Welcome, " + currentUsername_local + "!");
                            }
                            else {
                                serverSendMessage(clientSocket, "ERROR_REGISTRATION Server error during registration.");
                            }
                        }
                        else {
                            serverSendMessage(clientSocket, "ERROR_REGISTRATION User '" + tempUsername + "' already exists.");
                        }
                    }
                    else {
                        serverSendMessage(clientSocket, "ERROR_CMD Invalid registration format.");
                    }
                }
                else {
                    serverSendMessage(clientSocket, "ERROR_AUTH Please login or register.");
                }
            }
            else {
                if (cmd_token_upper == "LOGOUT") {
                    LOG_MSG(clientSocket, "LOGOUT command received for user '" + currentUsername_local + "'.");
                    {
                        std::lock_guard<std::mutex> lock(G_usersMutex);
                        auto it = G_connectedUsers.find(currentUsername_local);
                        if (it != G_connectedUsers.end() && it->second == clientSocket) {
                            G_connectedUsers.erase(it);
                            LOG_MSG(clientSocket, "User '" + currentUsername_local + "' removed from connected users due to LOGOUT.");
                            { std::lock_guard<std::mutex> log_lock(G_logMutex); logConnectedUsersInternal(); }
                        }
                    }
                    serverSendMessage(clientSocket, "OK_LOGOUT Goodbye, " + currentUsername_local + "!");
                    loggedIn_local = false;
                    // currentUsername_local is not cleared here intentionally, for the final cleanup block
                    break;
                }
                else if (cmd_token_upper == "SEND_PRIVATE") {
                    std::string recipient, message_content;
                    iss >> recipient;
                    iss >> std::ws;
                    std::getline(iss, message_content);

                    if (recipient.empty() || message_content.empty()) {
                        serverSendMessage(clientSocket, "ERROR_CMD Invalid SEND_PRIVATE format.");
                    }
                    else if (recipient == currentUsername_local) {
                        serverSendMessage(clientSocket, "ERROR_SEND Cannot send message to yourself.");
                    }
                    else if (!userExists(clientSocket, recipient)) {
                        serverSendMessage(clientSocket, "ERROR_SEND Recipient '" + recipient + "' does not exist.");
                    }
                    else {
                        std::string chatFile = getChatFilename(currentUsername_local, recipient);
                        std::string timestamp = getCurrentTimestamp();
                        std::string formatted_log_message = timestamp + ":" + currentUsername_local + ":" + message_content;

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
                                std::string fullMessage_to_recipient = "MSG_FROM " + currentUsername_local + ": " + message_content;
                                serverSendMessage(recipientSocket, fullMessage_to_recipient);
                            }
                            serverSendMessage(clientSocket, "OK_SENT Message to " + recipient + " processed.");

                        }
                        else {
                            LOG_SERVER_MSG("SEND_PRIVATE: CRITICAL - Failed to open chat log file '" + chatFile + "' for writing!");
                            serverSendMessage(clientSocket, "ERROR_SEND Server error, message not saved.");
                        }
                    }
                }
                else if (cmd_token_upper == "GET_HISTORY") {
                    std::string partner_username;
                    iss >> partner_username;
                    if (partner_username.empty()) { serverSendMessage(clientSocket, "ERROR_CMD Invalid GET_HISTORY: missing username."); }
                    else if (partner_username == currentUsername_local) { serverSendMessage(clientSocket, "NO_HISTORY " + partner_username); }
                    else if (!userExists(clientSocket, partner_username)) { serverSendMessage(clientSocket, "ERROR_CMD User '" + partner_username + "' does not exist for history request."); }
                    else {
                        std::string chat_file = getChatFilename(currentUsername_local, partner_username);
                        std::vector<std::string> history_entries;
                        std::ifstream history_ifs(chat_file);
                        if (history_ifs.is_open()) {
                            std::string line;
                            while (std::getline(history_ifs, line)) {
                                if (!line.empty()) history_entries.push_back(line);
                            }
                            history_ifs.close(); // Закрываем файл после чтения
                        }

                        if (!history_entries.empty()) {
                            serverSendMessage(clientSocket, "HISTORY_START " + partner_username);
                            for (const std::string& entry : history_entries) {
                                serverSendMessage(clientSocket, "HIST_MSG " + entry);
                            }
                            serverSendMessage(clientSocket, "HISTORY_END " + partner_username);
                        }
                        else {
                            serverSendMessage(clientSocket, "NO_HISTORY " + partner_username);
                        }
                    }
                }
                else if (cmd_token_upper == "GET_CHAT_PARTNERS") {
                    LOG_MSG(clientSocket, "GET_CHAT_PARTNERS request from " + currentUsername_local);
                    std::vector<std::pair<std::string, std::string>> chatPartnersStatus;
                    std::set<std::string> foundPartners;

                    try {
                        for (const auto& entry : std::filesystem::directory_iterator(G_chatLogsDir)) {
                            if (entry.is_regular_file()) {
                                std::string filename = entry.path().filename().string();
                                if (filename.rfind("chat_", 0) == 0 && filename.rfind(".txt") == filename.length() - 4) {
                                    std::string users_part = filename.substr(5, filename.length() - 9);
                                    size_t underscore_pos = users_part.find('_');
                                    if (underscore_pos != std::string::npos) {
                                        std::string user1 = users_part.substr(0, underscore_pos);
                                        std::string user2 = users_part.substr(underscore_pos + 1);
                                        std::string partner;

                                        if (user1 == currentUsername_local) partner = user2;
                                        else if (user2 == currentUsername_local) partner = user1;
                                        else continue;

                                        if (foundPartners.find(partner) == foundPartners.end()) {
                                            std::string status = "offline";
                                            {
                                                std::lock_guard<std::mutex> users_lock(G_usersMutex);
                                                if (G_connectedUsers.count(partner)) {
                                                    status = "online";
                                                }
                                            }
                                            chatPartnersStatus.push_back({ partner, status });
                                            foundPartners.insert(partner);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    catch (const std::filesystem::filesystem_error& fs_err) {
                        LOG_SERVER_MSG("Filesystem error in GET_CHAT_PARTNERS: " + std::string(fs_err.what()));
                        serverSendMessage(clientSocket, "ERROR_SERVER_FS_ERROR");
                        continue;
                    }

                    if (!chatPartnersStatus.empty()) {
                        serverSendMessage(clientSocket, "FRIEND_LIST_START");
                        for (const auto& partner_status : chatPartnersStatus) {
                            serverSendMessage(clientSocket, "FRIEND " + partner_status.first + " " + partner_status.second);
                        }
                        serverSendMessage(clientSocket, "FRIEND_LIST_END");
                    }
                    else {
                        serverSendMessage(clientSocket, "NO_FRIENDS_FOUND");
                    }
                }
                else {
                    serverSendMessage(clientSocket, "ERROR_CMD Unknown command when logged in.");
                }
            }
        }
    }
    catch (const std::exception& e) {
        LOG_MSG(clientSocket, "Exception in handleClient for user '" + (currentUsername_local.empty() ? "[unidentified]" : currentUsername_local) + "': " + e.what());
    }
    catch (...) {
        LOG_MSG(clientSocket, "Unknown exception in handleClient for user '" + (currentUsername_local.empty() ? "[unidentified]" : currentUsername_local) + "'");
    }

    if (!currentUsername_local.empty() && loggedIn_local) {
        std::lock_guard<std::mutex> lock(G_usersMutex);
        auto it = G_connectedUsers.find(currentUsername_local);
        if (it != G_connectedUsers.end() && it->second == clientSocket) {
            G_connectedUsers.erase(it);
            LOG_MSG(clientSocket, "User '" + currentUsername_local + "' removed from connected users due to connection drop/error.");
            { std::lock_guard<std::mutex> log_lock(G_logMutex); logConnectedUsersInternal(); }
        }
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

    LOG_SERVER_MSG("Server listening on port 8081 (with GET_CHAT_PARTNERS support, corrected logout)...");

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
#ifdef _WIN32
            if (error_code == WSAEINTR || error_code == WSAENOTSOCK || error_code == WSAECONNABORTED) {
                LOG_SERVER_MSG("accept likely interrupted or client closed. Error: " + std::to_string(error_code));
                if (error_code == WSAENOTSOCK) {
                    LOG_SERVER_MSG("Server socket no longer valid, attempting to shutdown server.");
                    break;
                }
            }
            else {
                LOG_SERVER_MSG("Accept failed with error: " + std::to_string(error_code) + ". Continuing...");
            }
#else 
            if (error_code == EINTR || error_code == EBADF || error_code == ECONNABORTED) {
                LOG_SERVER_MSG("accept likely interrupted or client closed. Error: " + std::to_string(error_code));
                if (error_code == EBADF) {
                    LOG_SERVER_MSG("Server socket no longer valid, attempting to shutdown server.");
                    break;
                }
            }
            else {
                LOG_SERVER_MSG("Accept failed with error: " + std::to_string(error_code) + ". Continuing...");
            }
#endif
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

    LOG_SERVER_MSG("Server shutting down loop.");
    CLOSE_SOCKET(serverSocket);
    shutdownUserStore();
#ifdef _WIN32
    WSACleanup();
#endif
    LOG_SERVER_MSG("Server has shut down.");
    return 0;
}