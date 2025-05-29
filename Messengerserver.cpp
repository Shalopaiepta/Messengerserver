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
#include <filesystem>
#include <cctype>
#include <set>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cerrno>  
#include <cstring> 
#include <sys/stat.h>
#endif

// Кросс-платформенные определения
#ifdef _WIN32
typedef SOCKET SocketType;
#define INVALID_SOCKET_VALUE INVALID_SOCKET
#define SOCKET_ERROR_VALUE SOCKET_ERROR
#define CLOSE_SOCKET closesocket
#define GET_LAST_ERROR WSAGetLastError()
// For file operations, WSAGetLastError() is not appropriate.
// strerror(errno) will be used directly for C-style file functions.
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


const std::string G_groupsIndexFileName = "groups_index.txt";
std::mutex G_groupsIndexMutex; // Защищает G_groups и операции с G_groupsIndexFileName

struct GroupInfo {
    std::string creator;
    std::set<std::string> members;
};
std::map<std::string, GroupInfo> G_groups;

std::string escapeGroupNameForFilename(const std::string& groupName) {
    std::string escapedName = groupName;
    std::replace_if(escapedName.begin(), escapedName.end(),
        [](char c) { return !std::isalnum(c) && c != '_'; },
        '_');
    return escapedName;
}

bool loadGroupsFromFile() {
    std::lock_guard<std::mutex> index_lock(G_groupsIndexMutex);
    std::ifstream inFile(G_groupsIndexFileName);
    if (!inFile.is_open()) {
        LOG_SERVER_MSG("Groups index file '" + G_groupsIndexFileName + "' not found. Will be created on first save.");
        return true; // Не ошибка, файл создастся при первом сохранении группы
    }
    LOG_SERVER_MSG("Loading groups from '" + G_groupsIndexFileName + "'...");
    G_groups.clear();
    std::string line;
    int line_num = 0;
    while (std::getline(inFile, line)) {
        line_num++;
        std::istringstream iss(line);
        std::string groupName, creator, members_str;
        if (std::getline(iss, groupName, ':') &&
            std::getline(iss, creator, ':') &&
            std::getline(iss, members_str)) {
            if (groupName.empty()) {
                LOG_SERVER_MSG("Skipping malformed line " + std::to_string(line_num) + " in groups index (empty group name): " + line);
                continue;
            }
            if (creator.empty()) {
                LOG_SERVER_MSG("Skipping malformed line " + std::to_string(line_num) + " in groups index (empty creator for group '" + groupName + "'): " + line);
                continue;
            }
            GroupInfo info; info.creator = creator;
            std::istringstream members_iss(members_str); std::string member;
            while (std::getline(members_iss, member, ',')) {
                if (!member.empty()) info.members.insert(member);
            }
            if (info.members.find(creator) == info.members.end()) { // Создатель всегда участник
                info.members.insert(creator);
            }
            G_groups[groupName] = info;
        }
        else {
            if (!line.empty()) { // Игнорировать пустые строки в конце файла
                LOG_SERVER_MSG("Malformed line " + std::to_string(line_num) + " in groups index: " + line);
            }
        }
    }
    LOG_SERVER_MSG("Finished loading " + std::to_string(G_groups.size()) + " group(s).");
    return true;
}

// Атомарное сохранение групп: запись во временный файл, удаление старого, переименование временного.
// G_groupsIndexMutex должен быть уже захвачен вызывающей функцией.
bool saveGroupsToFile() {
    LOG_SERVER_MSG("Attempting to save " + std::to_string(G_groups.size()) + " group(s) to file: " + G_groupsIndexFileName);
    std::string tempFileName = G_groupsIndexFileName + ".tmp";

    // 1. Запись во временный файл
    std::ofstream outFile(tempFileName, std::ios::trunc | std::ios::out);
    if (!outFile.is_open()) {
        LOG_SERVER_MSG("CRITICAL - Failed to open temporary groups index file '" + tempFileName + "' for writing. Check permissions/disk space.");
        return false;
    }
    for (const auto& pair : G_groups) {
        const std::string& groupName = pair.first;
        const GroupInfo& info = pair.second;
        outFile << groupName << ":" << info.creator << ":";
        bool first_member = true;
        for (const std::string& member : info.members) {
            if (!first_member) outFile << ",";
            outFile << member;
            first_member = false;
        }
        outFile << std::endl;
        if (!outFile.good()) {
            LOG_SERVER_MSG("CRITICAL - Error writing group '" + groupName + "' to temporary file '" + tempFileName + "'! Disk full or I/O error?");
            outFile.close();
            std::remove(tempFileName.c_str()); // Попытка очистки
            return false;
        }
    }
    outFile.flush();
    if (outFile.fail()) {
        LOG_SERVER_MSG("CRITICAL - Error flushing temporary file '" + tempFileName + "'. State: " << outFile.rdstate());
        outFile.close();
        std::remove(tempFileName.c_str());
        return false;
    }
    outFile.close();
    if (outFile.fail()) {
        LOG_SERVER_MSG("CRITICAL - Error closing temporary file '" + tempFileName + "'. State: " << outFile.rdstate());
        std::remove(tempFileName.c_str());
        return false;
    }
    LOG_SERVER_MSG("Successfully wrote data to temporary file: " + tempFileName);

    // 2. Удаление старого оригинального файла (если существует)
    bool original_file_existed = false;
    try {
        original_file_existed = std::filesystem::exists(G_groupsIndexFileName);
    }
    catch (const std::filesystem::filesystem_error& e) {
        LOG_SERVER_MSG("CRITICAL - Filesystem error checking existence of '" + G_groupsIndexFileName + "': " + e.what() + ". Aborting save.");
        std::remove(tempFileName.c_str()); // Очистка временного файла
        return false;
    }

    if (original_file_existed) {
        try { // Проверка на случай, если tempFileName и G_groupsIndexFileName указывают на один и тот же файл (логическая ошибка)
            if (std::filesystem::equivalent(G_groupsIndexFileName, tempFileName)) {
                LOG_SERVER_MSG("CRITICAL - Temp and original files are equivalent ('" + tempFileName + "'). Logic error. Aborting save.");
                // Не удаляем tempFileName, т.к. он и есть "оригинал" в этой ситуации
                return false;
            }
        }
        catch (const std::filesystem::filesystem_error& e) {
            LOG_SERVER_MSG("Warning - Filesystem error checking equivalence for '" + G_groupsIndexFileName + "' & '" + tempFileName + "': " + e.what() + ". Proceeding cautiously.");
        }

        if (std::remove(G_groupsIndexFileName.c_str()) != 0) {
            // ENOENT (No such file or directory) - не критично, если файл исчез между exists() и remove().
            if (errno == ENOENT) {
                LOG_SERVER_MSG("Info - Old groups index file '" + G_groupsIndexFileName + "' not found during removal (ENOENT). Proceeding.");
            }
            else { // Другие ошибки (EBUSY, EACCES) - критичны.
                LOG_SERVER_MSG("CRITICAL - Could not remove old groups index file '" + G_groupsIndexFileName + "'. Error (" + std::to_string(errno) + "): " + strerror(errno) + ". Aborting save.");
                std::remove(tempFileName.c_str()); // Очистка временного файла
                return false;
            }
        }
        else {
            LOG_SERVER_MSG("Successfully removed old groups index file: " + G_groupsIndexFileName);
        }
    }
    else {
        LOG_SERVER_MSG("Old groups index file '" + G_groupsIndexFileName + "' did not exist. No removal needed.");
    }

    // 3. Переименование временного файла в оригинальный
    if (std::rename(tempFileName.c_str(), G_groupsIndexFileName.c_str()) != 0) {
        LOG_SERVER_MSG("CRITICAL - Failed to rename temp file '" + tempFileName + "' to '" + G_groupsIndexFileName + "'. Error (" + std::to_string(errno) + "): " + strerror(errno) + ".");
        std::remove(tempFileName.c_str()); // Попытка очистки временного файла
        // Данные в temp, старый файл (если был) удален. Плохое состояние для восстановления.
        return false;
    }

    LOG_SERVER_MSG("Successfully saved " + std::to_string(G_groups.size()) + " group(s) to '" + G_groupsIndexFileName + "'.");
    return true;
}


void logConnectedUsersInternal() {
    std::cout << "Connected users: ";
    if (G_connectedUsers.empty()) { std::cout << "None"; }
    else { for (const auto& user : G_connectedUsers) { std::cout << user.first << "(" << user.second << ") "; } }
    std::cout << "\n";
}
void logConnectedUsers() { std::lock_guard<std::mutex> lock(G_usersMutex); std::lock_guard<std::mutex> log_lock(G_logMutex); logConnectedUsersInternal(); }

void ensureDirectoryExists(const std::string& path) {
    if (!std::filesystem::exists(path)) {
        try {
            if (std::filesystem::create_directories(path)) { // create_directories создает и родительские пути
                LOG_SERVER_MSG("Created directory: " + path);
            }
            else {
                // Перепроверка на случай конкурентного создания или если директория уже существовала
                if (!std::filesystem::exists(path)) {
                    LOG_SERVER_MSG("Failed to create directory (create_directories returned false and it doesn't exist): " + path);
                }
                else {
                    LOG_SERVER_MSG("Directory " + path + " now exists (possibly created concurrently or already existed).");
                }
            }
        }
        catch (const std::filesystem::filesystem_error& e) {
            LOG_SERVER_MSG("Error creating directory '" + path + "': " + std::string(e.what()));
        }
    }
}
bool loadCredentialsFromFile() {
    std::ifstream inFile(G_credentialsFileName);
    if (!inFile.is_open()) { LOG_SERVER_MSG("Credentials file '" + G_credentialsFileName + "' not found. Will be created on first registration."); return true; }
    LOG_SERVER_MSG("Loading credentials from '" + G_credentialsFileName + "'...");
    G_usersCredentials.clear(); std::string line; int count = 0;
    while (std::getline(inFile, line)) {
        std::istringstream iss(line); std::string username, password;
        // Удаление пробельных символов, особенно '\r' из Windows-концов строк
        auto trim = [](std::string& s) {
            s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](unsigned char ch) { return !std::isspace(ch); }));
            s.erase(std::find_if(s.rbegin(), s.rend(), [](unsigned char ch) { return !std::isspace(ch); }).base(), s.end());
        };

        if (std::getline(iss, username, ':') && std::getline(iss, password)) {
            trim(username);
            trim(password);
            if (!username.empty() && !password.empty()) {
                G_usersCredentials[username] = password; count++;
            }
            else if (!username.empty() && password.empty()) { // Разрешаем пустой пароль, но логируем
                LOG_SERVER_MSG("Warning: User '" + username + "' has an empty password in credentials file.");
                G_usersCredentials[username] = password; count++;
            }
            else if (!line.empty() && !(username.empty() && password.empty())) { // Логируем, если не пустая строка, но парсинг не удался
                LOG_SERVER_MSG("Malformed line in credentials file (after trim): " + line);
            }
        }
        else { if (!line.empty()) LOG_SERVER_MSG("Malformed line in credentials file (structure): " + line); }
    }
    LOG_SERVER_MSG("Loaded " + std::to_string(count) + " user(s)."); return true;
}
bool initUserStore() {
    std::lock_guard<std::mutex> cred_lock(G_credentialsMutex);
    // G_groupsIndexMutex блокируется внутри loadGroupsFromFile
    LOG_SERVER_MSG("User store initializing (file-based).");
    ensureDirectoryExists(G_chatLogsDir);
    bool creds_ok = loadCredentialsFromFile();
    bool groups_ok = loadGroupsFromFile();
    return creds_ok && groups_ok;
}
void shutdownUserStore() { LOG_SERVER_MSG("User store (file-based) shut down."); }
std::string serverReadLine(SocketType socket) {
    std::string line; char ch;
    while (true) {
        int bytesReceived = recv(socket, &ch, 1, 0);
        if (bytesReceived == 0) { LOG_MSG(socket, "Client disconnected gracefully."); return ""; }
        if (bytesReceived < 0) {
#ifdef _WIN32
            int error = WSAGetLastError();
            if (error == WSAECONNRESET || error == WSAESHUTDOWN || error == WSAEINTR) { // Обычные ошибки разрыва соединения
                LOG_MSG(socket, "recv failed (connection issue): " + std::to_string(error)); return "";
            }
#else
            if (errno == ECONNRESET || errno == EPIPE || errno == EINTR) { // Обычные ошибки разрыва соединения
                LOG_MSG(socket, "recv failed (connection issue): " + strerror(errno)); return "";
            }
#endif
            LOG_MSG(socket, "recv failed: " + GET_LAST_ERROR_STR); return ""; // Другая ошибка recv
        }
        if (ch == '\n') break;
        if (ch != '\r') line += ch; // Игнорируем '\r'
    }
    LOG_MSG(socket, "Received: \"" + line + "\""); return line;
}
void serverSendMessage(SocketType socket, const std::string& message) {
    std::string msg = message + "\n"; int msg_len = static_cast<int>(msg.length()); int bytesSentTotal = 0;
    while (bytesSentTotal < msg_len) {
        int bytesSent = send(socket, msg.c_str() + bytesSentTotal, msg_len - bytesSentTotal, 0);
        if (bytesSent == SOCKET_ERROR_VALUE) {
#ifdef _WIN32
            int error = WSAGetLastError();
            if (error == WSAECONNRESET || error == WSAESHUTDOWN || error == WSAENOTSOCK || error == WSAEINTR) {
                LOG_MSG(socket, "Send failed (connection issue): " + std::to_string(error)); return;
            }
#else
            if (errno == ECONNRESET || errno == EPIPE || errno == EBADF || errno == EINTR) {
                LOG_MSG(socket, "Send failed (connection issue): " + strerror(errno)); return;
            }
#endif
            LOG_MSG(socket, "Send failed: " + GET_LAST_ERROR_STR); return;
        }
        bytesSentTotal += bytesSent;
    }
    // Логируем только значащие сообщения, чтобы не засорять вывод (например, не каждую строку истории)
    if (!message.empty() && message.rfind("HIST_MSG", 0) != 0 && message.rfind("GROUP_HIST_MSG", 0) != 0) {
        LOG_MSG(socket, "Sent: \"" + message + "\" (" + std::to_string(bytesSentTotal) + " bytes)");
    }
}
bool userExists(SocketType s, const std::string& username) { std::lock_guard<std::mutex> lock(G_credentialsMutex); return G_usersCredentials.count(username) > 0; }
bool verifyUser(SocketType s, const std::string& username, const std::string& password) {
    std::lock_guard<std::mutex> lock(G_credentialsMutex);
    auto it = G_usersCredentials.find(username);
    if (it != G_usersCredentials.end()) return (it->second == password);
    return false;
}
bool insertUser(SocketType s, const std::string& username, const std::string& password) {
    std::lock_guard<std::mutex> lock(G_credentialsMutex);
    if (G_usersCredentials.count(username)) return false; // Пользователь уже существует в памяти

    // Запись в файл, затем обновление G_usersCredentials
    std::ofstream outFile(G_credentialsFileName, std::ios::app);
    if (!outFile.is_open()) { LOG_SERVER_MSG("CRITICAL - Failed to open credentials file '" + G_credentialsFileName + "' for append!"); return false; }

    outFile << username << ":" << password << std::endl;
    if (!outFile.good()) {
        LOG_SERVER_MSG("CRITICAL - Failed to write to credentials file '" + G_credentialsFileName + "'!");
        outFile.close();
        // TODO: Рассмотреть откат частичной записи при ошибке.
        return false;
    }
    outFile.close();

    G_usersCredentials[username] = password; // Обновляем G_usersCredentials только после успешной записи в файл
    LOG_SERVER_MSG("User '" + username + "' registered and credentials saved."); return true;
}
std::string getChatFilename(const std::string& user1, const std::string& user2) {
    // Имя файла чата не зависит от порядка имен пользователей
    if (user1 < user2) return G_chatLogsDir + "chat_" + user1 + "_" + user2 + ".txt";
    return G_chatLogsDir + "chat_" + user2 + "_" + user1 + ".txt";
}
std::string getCurrentTimestamp() {
    auto now = std::chrono::system_clock::now(); auto in_time_t = std::chrono::system_clock::to_time_t(now); std::tm buf;
#ifdef _WIN32
    localtime_s(&buf, &in_time_t);
#else
    localtime_r(&in_time_t, &buf); // Потокобезопасная версия
#endif
    std::stringstream ss; ss << std::put_time(&buf, "%Y-%m-%d %H:%M:%S"); return ss.str();
}

void handleClient(SocketType clientSocket) {
    LOG_MSG(clientSocket, "New client handler started.");
    std::string currentUsername_local; // Имя пользователя для этого потока/сессии
    bool loggedIn_local = false;       // Статус логина для этого потока/сессии

    try {
        while (true) {
            std::string command_line = serverReadLine(clientSocket);
            if (command_line.empty()) break; // Клиент отключился или ошибка чтения

            std::istringstream iss(command_line);
            std::string cmd_token_from_client;
            iss >> cmd_token_from_client;
            std::string cmd_token_upper = cmd_token_from_client;
            std::transform(cmd_token_upper.begin(), cmd_token_upper.end(), cmd_token_upper.begin(),
                [](unsigned char c) { return std::toupper(c); }); // Команды регистронезависимы

            LOG_MSG(clientSocket, "Parsed command: '" + cmd_token_upper + "'");

            if (!loggedIn_local) { // Если пользователь еще не вошел в систему
                if (cmd_token_upper == "LOGIN") {
                    std::string tempUsername, password;
                    iss >> tempUsername >> password;
                    // TODO: Добавить валидацию содержимого имени пользователя/пароля
                    if (!tempUsername.empty() && !password.empty()) {
                        if (verifyUser(clientSocket, tempUsername, password)) {
                            std::lock_guard<std::mutex> lock(G_usersMutex); // для G_connectedUsers
                            if (G_connectedUsers.find(tempUsername) == G_connectedUsers.end()) { // Проверка, не залогинен ли уже
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
                        else { serverSendMessage(clientSocket, "ERROR_LOGIN Invalid username or password."); }
                    }
                    else { serverSendMessage(clientSocket, "ERROR_CMD Invalid login format. Usage: LOGIN <username> <password>"); }
                }
                else if (cmd_token_upper == "REGISTRATION") {
                    std::string tempUsername, password;
                    iss >> tempUsername >> password;
                    // TODO: Добавить валидацию сложности пароля
                    if (!tempUsername.empty() && !password.empty()) {
                        // userExists (проверяет G_usersCredentials) и insertUser (пишет в файл и G_usersCredentials)
                        // оба защищены G_credentialsMutex
                        if (!userExists(clientSocket, tempUsername)) { // Проверка существования перед вставкой
                            if (insertUser(clientSocket, tempUsername, password)) {
                                std::lock_guard<std::mutex> lock(G_usersMutex); // для G_connectedUsers
                                G_connectedUsers[tempUsername] = clientSocket;
                                currentUsername_local = tempUsername;
                                loggedIn_local = true;
                                LOG_MSG(clientSocket, "User '" + currentUsername_local + "' registered and logged in.");
                                { std::lock_guard<std::mutex> log_lock(G_logMutex); logConnectedUsersInternal(); }
                                serverSendMessage(clientSocket, "OK_REGISTERED Welcome, " + currentUsername_local + "!");
                            }
                            else { serverSendMessage(clientSocket, "ERROR_REGISTRATION Server error during registration. Please try again."); }
                        }
                        else { serverSendMessage(clientSocket, "ERROR_REGISTRATION User '" + tempUsername + "' already exists."); }
                    }
                    else { serverSendMessage(clientSocket, "ERROR_CMD Invalid registration format. Usage: REGISTRATION <username> <password>"); }
                }
                else { serverSendMessage(clientSocket, "ERROR_AUTH Please login or register first."); }
            }
            else { // Пользователь залогинен (loggedIn_local == true)
                if (cmd_token_upper == "CREATE_GROUP") {
                    std::string groupName;
                    iss >> std::ws; // Пропустить пробелы
                    std::getline(iss, groupName); // Имя группы может содержать пробелы

                    if (groupName.empty()) {
                        serverSendMessage(clientSocket, "ERROR_CMD Group name cannot be empty.");
                    }
                    else if (groupName.length() > 50) { // Примерное ограничение длины
                        serverSendMessage(clientSocket, "ERROR_CMD Group name too long (max 50 chars).");
                    }
                    else if (groupName.find(':') != std::string::npos || groupName.find(',') != std::string::npos) {
                        serverSendMessage(clientSocket, "ERROR_CMD Group name contains invalid characters (':' or ',').");
                    }
                    else {
                        std::lock_guard<std::mutex> index_lock(G_groupsIndexMutex);
                        if (G_groups.count(groupName)) {
                            serverSendMessage(clientSocket, "ERROR_GROUP_EXISTS Group '" + groupName + "' already exists.");
                        }
                        else {
                            GroupInfo newGroup;
                            newGroup.creator = currentUsername_local;
                            newGroup.members.insert(currentUsername_local); // Создатель автоматически член группы
                            G_groups[groupName] = newGroup;

                            if (saveGroupsToFile()) {
                                serverSendMessage(clientSocket, "OK_GROUP_CREATED " + groupName);
                                LOG_MSG(clientSocket, "User '" + currentUsername_local + "' created group '" + groupName + "'.");
                            }
                            else {
                                serverSendMessage(clientSocket, "ERROR_SERVER Could not save group information. Group creation failed.");
                                G_groups.erase(groupName); // Откат: удаление из G_groups при ошибке сохранения
                            }
                        }
                    }
                }
                else if (cmd_token_upper == "JOIN_GROUP") {
                    std::string groupName; iss >> groupName;
                    if (groupName.empty()) { serverSendMessage(clientSocket, "ERROR_CMD JOIN_GROUP requires a group name."); }
                    else {
                        std::lock_guard<std::mutex> index_lock(G_groupsIndexMutex);
                        auto group_it = G_groups.find(groupName);
                        if (group_it == G_groups.end()) {
                            serverSendMessage(clientSocket, "ERROR_GROUP_NOT_FOUND Group '" + groupName + "' does not exist.");
                        }
                        else if (group_it->second.members.count(currentUsername_local)) {
                            serverSendMessage(clientSocket, "INFO_ALREADY_MEMBER You are already a member of group '" + groupName + "'.");
                        }
                        else {
                            group_it->second.members.insert(currentUsername_local);
                            if (saveGroupsToFile()) {
                                serverSendMessage(clientSocket, "OK_JOINED_GROUP " + groupName);
                                LOG_MSG(clientSocket, "User '" + currentUsername_local + "' joined group '" + groupName + "'.");

                                // Уведомление других участников группы
                                std::string notification = "USER_JOINED_GROUP " + groupName + " " + currentUsername_local;
                                std::lock_guard<std::mutex> users_lock(G_usersMutex);
                                for (const std::string& member : group_it->second.members) {
                                    if (member != currentUsername_local) { // Не уведомлять себя
                                        auto member_sock_it = G_connectedUsers.find(member);
                                        if (member_sock_it != G_connectedUsers.end()) { // Если участник онлайн
                                            serverSendMessage(member_sock_it->second, notification);
                                        }
                                    }
                                }
                            }
                            else {
                                serverSendMessage(clientSocket, "ERROR_SERVER Could not save group membership. Join failed.");
                                group_it->second.members.erase(currentUsername_local); // Откат
                            }
                        }
                    }
                }
                else if (cmd_token_upper == "SEND_GROUP") {
                    std::string groupName, message_content;
                    iss >> groupName;
                    iss >> std::ws;
                    std::getline(iss, message_content);

                    if (groupName.empty() || message_content.empty()) {
                        serverSendMessage(clientSocket, "ERROR_CMD Invalid SEND_GROUP format. Usage: SEND_GROUP <groupname> <message>");
                    }
                    else {
                        std::lock_guard<std::mutex> index_lock(G_groupsIndexMutex);
                        auto group_it = G_groups.find(groupName);
                        if (group_it == G_groups.end()) {
                            serverSendMessage(clientSocket, "ERROR_GROUP_NOT_FOUND Group '" + groupName + "' does not exist.");
                        }
                        else if (group_it->second.members.find(currentUsername_local) == group_it->second.members.end()) {
                            serverSendMessage(clientSocket, "ERROR_NOT_MEMBER You are not a member of group '" + groupName + "'.");
                        }
                        else {
                            ensureDirectoryExists(G_chatLogsDir);
                            std::string groupChatFile = G_chatLogsDir + "group_" + escapeGroupNameForFilename(groupName) + ".txt";
                            std::string timestamp = getCurrentTimestamp();
                            std::string log_message = timestamp + ":" + currentUsername_local + ":" + message_content;

                            std::ofstream group_log_file(groupChatFile, std::ios::app);
                            if (group_log_file.is_open()) {
                                group_log_file << log_message << std::endl;
                                group_log_file.close();
                            }
                            else {
                                serverSendMessage(clientSocket, "ERROR_SERVER Could not write to group chat log for '" + groupName + "'.");
                                // Политика: Продолжать отправку онлайн-участникам даже при ошибке логирования.
                            }

                            std::string msg_to_members = "GROUP_MSG_FROM " + groupName + " " + currentUsername_local + ": " + message_content;
                            std::lock_guard<std::mutex> users_lock(G_usersMutex);
                            int recipients = 0;
                            for (const std::string& member : group_it->second.members) {
                                if (member != currentUsername_local) { // Не отправлять себе
                                    auto member_sock_it = G_connectedUsers.find(member);
                                    if (member_sock_it != G_connectedUsers.end()) {
                                        serverSendMessage(member_sock_it->second, msg_to_members);
                                        recipients++;
                                    }
                                }
                            }
                            serverSendMessage(clientSocket, "OK_GROUP_MSG_SENT " + groupName + " (to " + std::to_string(recipients) + " online members)");
                            LOG_MSG(clientSocket, "User '" + currentUsername_local + "' sent to group '" + groupName + "': " + message_content);
                        }
                    }
                }
                else if (cmd_token_upper == "GROUPCHAT") { // Клиент шлет GROUPCHAT для получения истории группы
                    std::string groupName; iss >> groupName;
                    if (groupName.empty()) { serverSendMessage(clientSocket, "ERROR_CMD GROUPCHAT requires a group name."); }
                    else {
                        std::lock_guard<std::mutex> index_lock(G_groupsIndexMutex);
                        auto group_it = G_groups.find(groupName);
                        if (group_it == G_groups.end()) {
                            serverSendMessage(clientSocket, "ERROR_GROUP_NOT_FOUND Group '" + groupName + "' does not exist.");
                        }
                        else if (group_it->second.members.find(currentUsername_local) == group_it->second.members.end()) {
                            serverSendMessage(clientSocket, "ERROR_NOT_MEMBER You are not a member of group '" + groupName + "' and cannot view its history.");
                        }
                        else {
                            std::string groupChatFile = G_chatLogsDir + "group_" + escapeGroupNameForFilename(groupName) + ".txt";
                            std::ifstream historyFile(groupChatFile);
                            if (historyFile.is_open()) {
                                serverSendMessage(clientSocket, "GROUP_HISTORY_START " + groupName);
                                std::string line;
                                while (std::getline(historyFile, line)) {
                                    if (!line.empty()) serverSendMessage(clientSocket, "GROUP_HIST_MSG " + line);
                                }
                                historyFile.close();
                                serverSendMessage(clientSocket, "GROUP_HISTORY_END " + groupName);
                            }
                            else { serverSendMessage(clientSocket, "NO_GROUP_HISTORY " + groupName); }
                        }
                    }
                }
                else if (cmd_token_upper == "LIST_MY_GROUPS") {
                    LOG_MSG(clientSocket, "LIST_MY_GROUPS request from " + currentUsername_local);
                    std::vector<std::string> my_groups_names;
                    {
                        std::lock_guard<std::mutex> index_lock(G_groupsIndexMutex);
                        for (const auto& group_pair : G_groups) {
                            if (group_pair.second.members.count(currentUsername_local)) {
                                my_groups_names.push_back(group_pair.first);
                            }
                        }
                    }
                    std::sort(my_groups_names.begin(), my_groups_names.end()); // Для консистентного вывода

                    if (!my_groups_names.empty()) {
                        serverSendMessage(clientSocket, "MY_GROUPS_START");
                        for (const std::string& g_name : my_groups_names) {
                            serverSendMessage(clientSocket, "MY_GROUP_ENTRY " + g_name);
                        }
                        serverSendMessage(clientSocket, "MY_GROUPS_END");
                    }
                    else { serverSendMessage(clientSocket, "NO_GROUPS_JOINED"); }
                }
                else if (cmd_token_upper == "SEND_PRIVATE") {
                    std::string recipient, message_content_full;
                    iss >> recipient;
                    iss >> std::ws;
                    std::getline(iss, message_content_full);

                    if (recipient.empty() || message_content_full.empty()) {
                        serverSendMessage(clientSocket, "ERROR_CMD Invalid SEND_PRIVATE format. Usage: SEND_PRIVATE <recipient> <message>");
                    }
                    else if (recipient == currentUsername_local) {
                        serverSendMessage(clientSocket, "ERROR_SEND Cannot send private message to yourself.");
                    }
                    else if (!userExists(clientSocket, recipient)) { // Проверяет G_usersCredentials
                        serverSendMessage(clientSocket, "ERROR_SEND Recipient user '" + recipient + "' not found.");
                    }
                    else {
                        ensureDirectoryExists(G_chatLogsDir);
                        std::string chatFile = getChatFilename(currentUsername_local, recipient);
                        std::string timestamp = getCurrentTimestamp();
                        std::string log_entry = timestamp + ":" + currentUsername_local + ":" + message_content_full;

                        std::ofstream chat_log_file(chatFile, std::ios::app);
                        if (chat_log_file.is_open()) {
                            chat_log_file << log_entry << std::endl;
                            chat_log_file.close();
                        }
                        else {
                            serverSendMessage(clientSocket, "ERROR_SEND Server error: Could not save private message to log.");
                            // Политика: Продолжать отправку, если получатель онлайн, даже при ошибке логирования.
                        }

                        SocketType recipientSocket = INVALID_SOCKET_VALUE;
                        {
                            std::lock_guard<std::mutex> users_lock(G_usersMutex);
                            auto it = G_connectedUsers.find(recipient);
                            if (it != G_connectedUsers.end()) recipientSocket = it->second;
                        }

                        if (recipientSocket != INVALID_SOCKET_VALUE) { // Если получатель онлайн
                            serverSendMessage(recipientSocket, "MSG_FROM " + currentUsername_local + ": " + message_content_full);
                        }
                        // Подтверждение отправителю, даже если получатель офлайн (сообщение залогировано)
                        serverSendMessage(clientSocket, "OK_SENT Message to " + recipient + " processed.");
                        LOG_MSG(clientSocket, "User '" + currentUsername_local + "' sent private to '" + recipient + "': " + message_content_full);
                    }
                }
                else if (cmd_token_upper == "GET_HISTORY") { // Для приватных чатов
                    std::string otherUsername; iss >> otherUsername;
                    if (otherUsername.empty()) {
                        serverSendMessage(clientSocket, "ERROR_CMD Invalid GET_HISTORY format. Usage: GET_HISTORY <username>");
                    }
                    else if (otherUsername == currentUsername_local) {
                        serverSendMessage(clientSocket, "NO_HISTORY " + otherUsername); // Нет истории с самим собой в этом контексте
                    }
                    else if (!userExists(clientSocket, otherUsername)) {
                        serverSendMessage(clientSocket, "ERROR_CMD User '" + otherUsername + "' not found for history retrieval.");
                    }
                    else {
                        std::string chatFile = getChatFilename(currentUsername_local, otherUsername);
                        std::ifstream historyFile(chatFile);
                        if (historyFile.is_open()) {
                            serverSendMessage(clientSocket, "HISTORY_START " + otherUsername);
                            std::string line;
                            while (std::getline(historyFile, line)) {
                                if (!line.empty()) serverSendMessage(clientSocket, "HIST_MSG " + line);
                            }
                            historyFile.close();
                            serverSendMessage(clientSocket, "HISTORY_END " + otherUsername);
                        }
                        else { serverSendMessage(clientSocket, "NO_HISTORY " + otherUsername); }
                    }
                }
                else if (cmd_token_upper == "GET_CHAT_PARTNERS") { // Клиент называет это "FRIENDS"
                    LOG_MSG(clientSocket, "GET_CHAT_PARTNERS request from " + currentUsername_local);
                    std::vector<std::pair<std::string, std::string>> chatPartnersStatus;
                    std::set<std::string> foundPartners; // Для избежания дубликатов (не должно случаться с getChatFilename)

                    try {
                        if (std::filesystem::exists(G_chatLogsDir) && std::filesystem::is_directory(G_chatLogsDir)) {
                            for (const auto& entry : std::filesystem::directory_iterator(G_chatLogsDir)) {
                                if (entry.is_regular_file()) {
                                    std::string filename = entry.path().filename().string();
                                    // Проверка формата "chat_user1_user2.txt"
                                    if (filename.rfind("chat_", 0) == 0 && filename.length() > 9 && filename.rfind(".txt") == filename.length() - 4) {
                                        std::string users_part = filename.substr(5, filename.length() - 9); // Убираем "chat_" и ".txt"
                                        size_t underscore_pos = users_part.find('_');
                                        if (underscore_pos != std::string::npos && underscore_pos > 0 && underscore_pos < users_part.length() - 1) {
                                            std::string user1 = users_part.substr(0, underscore_pos);
                                            std::string user2 = users_part.substr(underscore_pos + 1);
                                            std::string partner;

                                            if (user1 == currentUsername_local) partner = user2;
                                            else if (user2 == currentUsername_local) partner = user1;
                                            else continue; // Файл не относится к текущему пользователю

                                            if (foundPartners.find(partner) == foundPartners.end()) { // Новый партнер
                                                std::string status = "offline";
                                                {
                                                    std::lock_guard<std::mutex> users_lock(G_usersMutex);
                                                    if (G_connectedUsers.count(partner)) status = "online";
                                                }
                                                chatPartnersStatus.push_back({ partner, status });
                                                foundPartners.insert(partner);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        else {
                            LOG_SERVER_MSG("Warning: Chat logs directory '" + G_chatLogsDir + "' does not exist or is not a directory.");
                        }
                    }
                    catch (const std::filesystem::filesystem_error& fs_err) {
                        LOG_SERVER_MSG("Filesystem error during GET_CHAT_PARTNERS for " + currentUsername_local + ": " + fs_err.what());
                        serverSendMessage(clientSocket, "ERROR_SERVER_FS_ERROR Could not list chat partners.");
                        continue; // Пропускаем остальную часть этого запроса
                    }

                    std::sort(chatPartnersStatus.begin(), chatPartnersStatus.end()); // Для консистентного вывода

                    if (!chatPartnersStatus.empty()) {
                        serverSendMessage(clientSocket, "FRIEND_LIST_START"); // Клиент ожидает это
                        for (const auto& ps : chatPartnersStatus) {
                            serverSendMessage(clientSocket, "FRIEND " + ps.first + " " + ps.second);
                        }
                        serverSendMessage(clientSocket, "FRIEND_LIST_END");
                    }
                    else { serverSendMessage(clientSocket, "NO_FRIENDS_FOUND"); } // Клиент ожидает это
                }
                else if (cmd_token_upper == "LOGOUT") {
                    LOG_MSG(clientSocket, "LOGOUT command received for user '" + currentUsername_local + "'.");
                    std::string userToLogout = currentUsername_local; // Копируем имя перед очисткой
                    loggedIn_local = false; // Меняем статус для этого обработчика
                    currentUsername_local.clear();

                    {
                        std::lock_guard<std::mutex> lock(G_usersMutex);
                        auto it = G_connectedUsers.find(userToLogout);
                        // Удаляем из G_connectedUsers только если сокет совпадает (этот клиент)
                        if (it != G_connectedUsers.end() && it->second == clientSocket) {
                            G_connectedUsers.erase(it);
                            LOG_MSG(clientSocket, "User '" + userToLogout + "' removed from connected users map.");
                            { std::lock_guard<std::mutex> log_lock(G_logMutex); logConnectedUsersInternal(); }
                        }
                        else if (it != G_connectedUsers.end()) { // Пользователь есть, но сокет другой
                            LOG_MSG(clientSocket, "Warning: User '" + userToLogout + "' found in connected map, but with different socket. Not removing.");
                        }
                        else { // Пользователя нет в карте (маловероятно при корректном LOGOUT)
                            LOG_MSG(clientSocket, "Warning: User '" + userToLogout + "' not found in connected map during logout.");
                        }
                    }
                    serverSendMessage(clientSocket, "OK_LOGOUT Goodbye, " + userToLogout + "!");
                    // Клиент сам решает, закрывать ли соединение или логиниться снова.
                    // Если клиент закроет соединение, цикл while прервется.
                }
                else { serverSendMessage(clientSocket, "ERROR_CMD Unknown command or command not available in current state."); }
            }
        }
    }
    catch (const std::exception& e) {
        LOG_MSG(clientSocket, "Standard exception in client handler for " + (currentUsername_local.empty() ? "unidentified user" : currentUsername_local) + ": " + e.what());
    }
    catch (...) {
        LOG_MSG(clientSocket, "Unknown exception in client handler for " + (currentUsername_local.empty() ? "unidentified user" : currentUsername_local));
    }

    // Очистка при неожиданном разрыве соединения (если пользователь был залогинен в этом потоке)
    if (!currentUsername_local.empty() && loggedIn_local) {
        std::lock_guard<std::mutex> lock(G_usersMutex);
        auto it = G_connectedUsers.find(currentUsername_local);
        // Важно: удаляем только если сокет совпадает с сокетом этого потока
        if (it != G_connectedUsers.end() && it->second == clientSocket) {
            G_connectedUsers.erase(it);
            LOG_MSG(clientSocket, "User '" + currentUsername_local + "' (socket " + std::to_string(clientSocket) + ") disconnected and removed from connected list.");
            { std::lock_guard<std::mutex> log_lock(G_logMutex); logConnectedUsersInternal(); }
        }
        else if (it != G_connectedUsers.end()) {
            LOG_MSG(clientSocket, "User '" + currentUsername_local + "' found in connected list, but with different socket (" + std::to_string(it->second) + "). Not removing for this disconnect (socket " + std::to_string(clientSocket) + ").");
        }
    }
    LOG_MSG(clientSocket, "Closing connection for socket " + std::to_string(clientSocket) + ".");
    CLOSE_SOCKET(clientSocket);
    LOG_MSG(clientSocket, "Client handler finished for socket " + std::to_string(clientSocket) + ".");
}

int main() {
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        // std::cerr для критических ошибок до инициализации логгера
        std::cerr << "SERVER: WSAStartup failed. Error: " << WSAGetLastError() << std::endl;
        return 1;
    }
#endif
    if (!initUserStore()) { // Загрузка credentials и groups
        LOG_SERVER_MSG("CRITICAL - Failed to initialize user store. Server cannot start.");
#ifdef _WIN32 
        WSACleanup();
#endif        
        return 1;
    }

    SocketType serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == INVALID_SOCKET_VALUE) {
        LOG_SERVER_MSG("Socket creation failed: " + GET_LAST_ERROR_STR);
        shutdownUserStore();
#ifdef _WIN32 
        WSACleanup();
#endif        
        return 1;
    }

    // SO_REUSEADDR для быстрого перезапуска сервера
    int opt = 1;
#ifdef _WIN32
    if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt)) == SOCKET_ERROR_VALUE) {
        LOG_SERVER_MSG("setsockopt(SO_REUSEADDR) failed: " + GET_LAST_ERROR_STR); // Не фатально, но логируем
    }
#else
    if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == SOCKET_ERROR_VALUE) {
        LOG_SERVER_MSG("setsockopt(SO_REUSEADDR) failed: " + GET_LAST_ERROR_STR); // Не фатально
    }
#endif

    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY; // Слушать на всех доступных интерфейсах
    serverAddr.sin_port = htons(8081);       // Номер порта

    if (bind(serverSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR_VALUE) {
        LOG_SERVER_MSG("Bind failed: " + GET_LAST_ERROR_STR + ". Port 8081 might be in use.");
        CLOSE_SOCKET(serverSocket);
        shutdownUserStore();
#ifdef _WIN32 
        WSACleanup();
#endif        
        return 1;
    }

    if (listen(serverSocket, SOMAXCONN) == SOCKET_ERROR_VALUE) { // SOMAXCONN - разумный размер очереди
        LOG_SERVER_MSG("Listen failed: " + GET_LAST_ERROR_STR);
        CLOSE_SOCKET(serverSocket);
        shutdownUserStore();
#ifdef _WIN32 
        WSACleanup();
#endif        
        return 1;
    }
    LOG_SERVER_MSG("Server listening on port 8081...");

    // Главный цикл сервера для приема подключений
    while (true) {
        sockaddr_in clientAddr;
#ifdef _WIN32
        int addrLen = sizeof(clientAddr);
#else
        socklen_t addrLen = sizeof(clientAddr);
#endif
        SocketType clientSocket = accept(serverSocket, (sockaddr*)&clientAddr, &addrLen);

        if (clientSocket == INVALID_SOCKET_VALUE) {
            int err_code = GET_LAST_ERROR;
#ifdef _WIN32
            // WSAEINTR - accept прерван сигналом
            // WSAECONNABORTED - клиент закрыл соединение до завершения accept
            if (err_code == WSAEINTR || err_code == WSAECONNABORTED) {
                LOG_SERVER_MSG("accept() interrupted or aborted, continuing. Error: " + std::to_string(err_code));
                std::this_thread::sleep_for(std::chrono::milliseconds(20)); // Небольшая задержка
                continue;
            }
            // WSAENOTSOCK/WSAEINVAL - серверный сокет больше не валиден (критично)
            if (err_code == WSAENOTSOCK || err_code == WSAEINVAL) {
                LOG_SERVER_MSG("Critical accept error, server socket might be closed. Shutting down. Error: " + std::to_string(err_code));
                break; // Выход из цикла while
            }
#else // POSIX
            if (errno == EINTR || errno == ECONNABORTED) {
                LOG_SERVER_MSG("accept() interrupted or aborted, continuing. Error: " + strerror(errno));
                std::this_thread::sleep_for(std::chrono::milliseconds(20));
                continue;
            }
            // EBADF/EINVAL/ENOTSOCK - серверный сокет не валиден
            if (errno == EBADF || errno == EINVAL || errno == ENOTSOCK) {
                LOG_SERVER_MSG("Critical accept error, server socket might be closed. Shutting down. Error: " + strerror(errno));
                break; // Выход из цикла while
            }
#endif
            LOG_SERVER_MSG("accept() failed with unhandled error: " + GET_LAST_ERROR_STR + " (Code: " + std::to_string(err_code) + "). Continuing...");
            std::this_thread::sleep_for(std::chrono::milliseconds(100)); // Избегаем busy-loop при постоянных ошибках
            continue;
        }

        char clientIpStr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &clientAddr.sin_addr, clientIpStr, INET_ADDRSTRLEN);
        LOG_SERVER_MSG("Client accepted from " + std::string(clientIpStr) + ":" + std::to_string(ntohs(clientAddr.sin_port)) + " | Assigned to socket " + std::to_string(clientSocket));

        try {
            std::thread clientThread(handleClient, clientSocket);
            clientThread.detach(); // Поток клиента работает независимо
        }
        catch (const std::system_error& e) { // std::thread может выбросить std::system_error
            LOG_SERVER_MSG("Failed to create client thread (std::system_error): " + std::string(e.what()) + ". Closing client socket.");
            CLOSE_SOCKET(clientSocket);
        }
        catch (const std::exception& e) { // На всякий случай
            LOG_SERVER_MSG("Failed to create client thread (std::exception): " + std::string(e.what()) + ". Closing client socket.");
            CLOSE_SOCKET(clientSocket);
        }
        catch (...) {
            LOG_SERVER_MSG("Failed to create client thread (unknown exception). Closing client socket.");
            CLOSE_SOCKET(clientSocket);
        }
    }

    LOG_SERVER_MSG("Server shutting down main accept loop.");
    CLOSE_SOCKET(serverSocket);
    shutdownUserStore(); // Финальная очистка хранилища пользователей
#ifdef _WIN32
    WSACleanup();
#endif
    LOG_SERVER_MSG("Server has shut down.");
    return 0;
}