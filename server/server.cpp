#include <iostream>
#include <string>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <signal.h>
#include <fstream>
#include <netinet/tcp.h>
#include <ctime>
#include <fcntl.h>
#include <sys/select.h>
#include <vector>
#include <algorithm> 
#include <map>
#include <regex>
#include <sys/time.h>
#include <unordered_map>
#include <chrono>


#define BUFFER_SIZE 1024
#define SOH 0x01 // Start of message (ASCII 0x01)
#define EOT 0x04 // End of message (ASCII 0x04)
#define ESC 0x1B // Escape character for bytestuffing
#define MAX_PEERS 20
#define MESSAGE_LIMIT 5000

// Struct for client
struct Client {
    std::string id;
    std::string ip;
    int port;
    int sockfd; 
};

struct QueueEntry{
    std::string timestamp;
    std::string dest; 
    std::string source;
    std::string message;
};

// list of avaialbe commands
std::vector<std::string> COMMANDS = {"HELO", "SERVERS", "LISTSERVERS", "SENDMSG", "KEEPALIVE", "GETMSGS", "GETMSG", "STATUSREQ"};

std::string get_timestamp() {
    /**
     * @brief Retrieves the current timestamp as a formatted string.
     * 
     * This function fetches the current system time, formats it into
     * a human-readable "YYYY-MM-DD HH:MM:SS" format, and returns it
     * as a std::string.
     * 
     * @return std::string The current timestamp formatted as "YYYY-MM-DD HH:MM:SS".
     */
    std::time_t now = std::time(nullptr);
    char buf[100];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", std::localtime(&now));
    return std::string(buf);
}

std::string remove_escapes(const std::string &message) {
    /**
     * @brief Removes escape characters from a string.
     * 
     * This function processes the input string and removes any escape characters.
     * It skips over escape sequences, treating the character following an escape
     * (denoted by `ESC`) as a literal, and appends non-escaped characters to the 
     * result string.
     * 
     * @param message The input string potentially containing escape sequences.
     * @return std::string A new string with escape sequences removed.
     */
    std::string unescaped_message;
    bool escape_next = false;

    for (char ch : message) {
        if (escape_next) {
            unescaped_message.push_back(ch);
            escape_next = false;
        } else if (ch == ESC) {
            escape_next = true; // The next character is escaped
        } else {
            unescaped_message.push_back(ch);
        }
    }
    return unescaped_message;
}

void set_nonblocking(int sock) {
    /**
     * @brief Sets a socket to non-blocking mode.
    * 
    * This function modifies the file descriptor of a socket to make it non-blocking.
    * It retrieves the current file status flags using `fcntl`, adds the `O_NONBLOCK`
    * flag to the existing flags, and applies the new configuration to the socket.
    * 
    * @param sock The file descriptor of the socket to set to non-blocking mode.
    */

    int flags = fcntl(sock, F_GETFL, 0);
    if (flags == -1) flags = 0;
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
}

std::string apply_escapes(const std::string &message) {
    /**
     * @brief Applies escape sequences to specific characters in a string.
     * 
     * This function processes the input string and adds escape characters
     * before specific control characters (SOH, EOT, and ESC) to ensure that
     * they are treated as literals. The resulting string includes escape 
     * sequences for the specified characters.
     * 
     * @param message The input string to be processed for escape sequences.
     * @return std::string A new string with escape sequences applied.
     */

    std::string escaped_message;
    for (char ch : message) {
        if (ch == SOH || ch == EOT || ch == ESC) {
            escaped_message.push_back(ESC); // Add escape character
        }
        escaped_message.push_back(ch);
    }
    return escaped_message;
}

std::string message_handler(ssize_t bytes_received, char *buffer){
    /**
     * @brief Handles incoming messages from a buffer.
     * 
     * This function processes a buffer of received bytes to extract messages 
     * delimited by the Start of Heading (SOH) and End of Transmission (EOT) 
     * control characters. It accumulates bytes into a message buffer when 
     * receiving a message and removes escape sequences before returning 
     * the final message string.
     * 
     * @param bytes_received The number of bytes received in the buffer.
     * @param buffer A pointer to the buffer containing the received bytes.
     * @return std::string The extracted message with escape sequences removed.
     */

    std::string message;
    std::string message_buffer;
    bool receiving_message = false;

    for (ssize_t i = 0; i < bytes_received; i++){
        char byte = buffer[i];
        if (byte == SOH){
            message_buffer.clear();
            receiving_message = true;
        }else if (byte == EOT){
            receiving_message = false;
            message = remove_escapes(message_buffer);
        }else{
            if (receiving_message) message_buffer.push_back(byte);
        }
    }

    return message;
}

void message_parser(std::string message, std::vector<std::string> &parts){
    /**
     * @brief Parses a comma-separated message into individual parts.
    * 
    * This function takes a message string, uses a regular expression to 
    * split it by commas, and stores the resulting substrings into a vector. 
    * Each part of the message is extracted and added to the provided vector 
    * of strings.
    * 
    * @param message The input string containing the message to be parsed.
    * @param parts A reference to a vector that will store the extracted parts 
    *              of the message.
    */
    std::regex rgx("([^,]+)"); 
    std::smatch match;

    auto it = std::sregex_iterator(message.begin(), message.end(), rgx);
    auto end = std::sregex_iterator();

    while (it != end) {
        parts.push_back(it->str());
        ++it;
    }
}

std::string create_server_string(const std::string& my_group_name, const std::string& my_ip, int my_port, const std::vector<Client>& clients) {
    /**
     * @brief Constructs a server string containing group and client information.
     * 
     * This function generates a formatted string that includes the server's 
     * group name, IP address, port number, and a list of connected clients. 
     * Each client's details (ID, IP, and port) are appended to the string, 
     * separated by semicolons. The resulting string is formatted as:
     * "SERVERS,<group_name>,<ip>,<port>;<client_id>,<client_ip>,<client_port>".
     * 
     * @param my_group_name The name of the server's group.
     * @param my_ip The IP address of the server.
     * @param my_port The port number of the server.
     * @param clients A vector of Client objects representing connected clients.
     * @return std::string A formatted string with the server and client information.
     */

    std::ostringstream oss;
    oss << "SERVERS," << my_group_name << "," << my_ip << "," << my_port;
    for (const auto& client : clients) {
        oss << ";" << client.id << "," << client.ip << "," << client.port;
    }
    return oss.str();
}

void connect_to_peer(std::string name, const std::string &peer_ip, int peer_port, const std::string &my_group_id, std::vector<Client> &clients, fd_set &master_set, int &max_sd, std::ofstream &log_file, int timeout_sec) {
    /**
     * @brief Connects to a peer server and sends a HELLO message.
     * 
     * This function attempts to establish a TCP connection to a specified 
     * peer server identified by its IP address and port. If the connection 
     * is successful, it sends a framed HELLO message containing the group's 
     * ID to the peer. The function also manages the socket file descriptor 
     * within the master set for monitoring multiple sockets.
     * 
     * @param name The name of the group associated with the connection.
     * @param peer_ip The IP address of the peer server to connect to.
     * @param peer_port The port number of the peer server.
     * @param my_group_id The ID of the group initiating the connection.
     * @param clients A reference to a vector that holds the currently connected clients.
     * @param master_set A reference to the file descriptor set used for select.
     * @param max_sd A reference to the maximum socket descriptor in the master set.
     * @param log_file A reference to the output file stream for logging connection attempts.
     * @param timeout_sec The timeout period (in seconds) for the connection attempt.
     */

    int sockfd;
    struct sockaddr_in peer_addr;
    
    // Create socket
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        std::cerr << "Socket creation failed" << std::endl;
        return;
    }

    set_nonblocking(sockfd);

    peer_addr.sin_family = AF_INET;
    peer_addr.sin_port = htons(peer_port);
    if (inet_pton(AF_INET, peer_ip.c_str(), &peer_addr.sin_addr) <= 0) {
        std::cerr << "Invalid address or Address not supported" << std::endl;
        close(sockfd);
        return;
    }

    // Attempt to connect to the server
    int connect_result = connect(sockfd, (struct sockaddr *)&peer_addr, sizeof(peer_addr));
    if (connect_result < 0 && errno != EINPROGRESS) {
        std::cerr << "Connection to peer failed: " << peer_ip << ":" << peer_port << " - " << strerror(errno) << std::endl;
        close(sockfd);
        return;
    }

    // Set up fd_set for select
    fd_set write_fds;
    FD_ZERO(&write_fds);
    FD_SET(sockfd, &write_fds);

    // Set timeout to 1 second
    struct timeval timeout;
    timeout.tv_sec = timeout_sec;  // 5 seconds
    timeout.tv_usec = 0;

    // Wait for the socket to be writable
    int select_result = select(sockfd + 1, NULL, &write_fds, NULL, &timeout);

    if (select_result > 0) {
        // Check if the socket is writable
        if (FD_ISSET(sockfd, &write_fds)) {
            // Connection successful
            std::string framed_message;
            framed_message.push_back(SOH); // Start of Header
            framed_message += apply_escapes("HELO," + my_group_id);
            framed_message.push_back(EOT); // End of Transmission
            send(sockfd, framed_message.c_str(), framed_message.size(), 0);
            log_file << "[" << get_timestamp() << "] Sent message to "
                      << "Group: " << name // Will be set later when HELO is confirmed
                      << " IP: " << peer_ip
                      << ", Port: " << peer_port
                      << " - " << "HELO," + my_group_id << std::endl;

            // Add the connected peer to the clients list
            Client new_client;
            new_client.id = ""; // Will be set later when HELO is confirmed
            new_client.ip = peer_ip;
            new_client.port = peer_port;
            new_client.sockfd = sockfd;
            clients.push_back(new_client);

            // Add the new socket to the master set
            FD_SET(sockfd, &master_set);
            if (sockfd > max_sd) {
                max_sd = sockfd;
            }
        }
    } else if (select_result == 0) {
        // Timeout occurred
        std::cerr << "Connection to peer timed out: " << peer_ip << ":" << peer_port << std::endl;
        close(sockfd);
    } else {
        // An error occurred
        std::cerr << "select error: " << strerror(errno) << std::endl;
        close(sockfd);
    }
}

void get_queued_clients(std::fstream &file, std::vector<Client> &clients, std::vector<std::string> &queued_dests){
    /**
     * @brief Retrieves queued client destinations from a file.
     * 
     * This function reads lines from a given file and extracts information about 
     * queued messages. It checks the status of each entry, and if the status is 
     * "QUEUED", it verifies whether the destination is present in the list of 
     * connected clients. Valid queued destinations are added to the provided vector.
     * 
     * @param file A reference to a fstream object for reading the file containing queued messages.
     * @param clients A reference to a vector holding the currently connected clients.
     * @param queued_dests A reference to a vector that will store the IDs of queued destinations.
     */

    std::string line;
    while (std::getline(file, line)){
        std::stringstream ss(line);
        std::string timestamp, dest, src, message, status;

        std::getline(ss, timestamp, ';');
        std::getline(ss, dest, ';');
        std::getline(ss, src, ';');
        std::getline(ss, message, ';');
        std::getline(ss, status, ';');

        if (status == "QUEUED"){
            // check if queud dest is in clients
            for (const auto client : clients){
                if (client.id == dest){
                    queued_dests.push_back(dest);
                }
            }
        }
    }
}

void get_queued_messages(std::vector<QueueEntry> &queued_messages, std::string dest_group){
    /**
     * @brief Retrieves queued messages for a specific destination group.
     * 
     * This function reads from a log file containing messages and extracts 
     * queued entries. It checks the status of each entry, and if the status 
     * is "QUEUED", it adds the message to the provided vector if it matches 
     * the specified destination group. If no destination group is specified, 
     * all queued messages are added.
     * 
     * @param queued_messages A reference to a vector that will store the 
     *                       queued messages as QueueEntry objects.
     * @param dest_group The destination group for which queued messages 
     *                   are to be retrieved. If empty, all queued messages 
     *                   are included.
     */

    std::fstream file("server_A_56_messages_log.txt", std::ios::in | std::ios::out);
    std::string line;
    while (std::getline(file, line)){
        std::stringstream ss(line);
        std::string timestamp, dest, src, message, status;

        std::getline(ss, timestamp, ';');
        std::getline(ss, dest, ';');
        std::getline(ss, src, ';');
        std::getline(ss, message, ';');
        std::getline(ss, status, ';');

        if (status == "QUEUED"){
            if (dest_group == ""){
                QueueEntry info{timestamp, dest, src, message};
                queued_messages.push_back(info);
            }else{
                if (dest_group == dest){
                    QueueEntry info{timestamp, dest, src, message};
                    queued_messages.push_back(info);
                }
            }
           
        }
    }
}

void remove_line_with_timestamp(const std::string &timestamp) {
    /**
     * @brief Removes lines from a log file that match a specific timestamp.
     * 
     * This function opens a log file and creates a temporary file to store 
     * all lines except those that contain the specified timestamp. After reading 
     * all lines, it deletes the original log file and renames the temporary 
     * file to replace it, effectively removing the entries associated with 
     * the given timestamp.
     * 
     * @param timestamp The timestamp of the lines to be removed from the log file.
     */

    std::ifstream file("server_A_56_messages_log.txt");
    std::ofstream temp("temp.txt");

    std::string line;
    while (std::getline(file, line)) {
        std::stringstream ss(line);
        std::string time;
        std::getline(ss, time, ';');
        if (time != timestamp) {
            temp << line << std::endl;
        }
    }

    file.close();
    temp.close();
    remove("server_A_56_messages_log.txt");
    rename("temp.txt", "server_A_56_messages_log.txt");
}

void get_client_socket(std::vector<Client> &clients, std::string dest, int &sockfd){
    /**
     * @brief Retrieves the socket file descriptor for a specified client.
     * 
     * This function searches through a vector of connected clients to find 
     * the client with the specified ID. If the client is found, it assigns 
     * the client's socket file descriptor to the provided reference variable.
     * 
     * @param clients A reference to a vector containing currently connected clients.
     * @param dest The ID of the client whose socket file descriptor is to be retrieved.
     * @param sockfd A reference to an integer where the client's socket file 
     *                descriptor will be stored if found.
     */

    for (const auto client : clients){
        if (client.id == dest){
            sockfd = client.sockfd;
            break;
        }
    }
}

void get_client_info(std::vector<Client> &clients, std::string dest, std::string &ip, int &port){
    /**
     * @brief Retrieves the IP address and port number of a specified client.
     * 
     * This function searches through a vector of connected clients to find 
     * the client with the specified ID. If the client is found, it assigns 
     * the client's IP address and port number to the provided reference variables.
     * 
     * @param clients A reference to a vector containing currently connected clients.
     * @param dest The ID of the client whose IP address and port number are to be retrieved.
     * @param ip A reference to a string where the client's IP address will be stored if found.
     * @param port A reference to an integer where the client's port number will be stored if found.
     */

    for (const auto client : clients){
        if (client.id == dest){
            ip = client.ip;
            port = client.port;
            break;
        }
    }
}

void queueHandler(std::vector<Client> &clients, std::ofstream &log_file, std::ofstream &msgs_log_file){
    /**
     * @brief Handles queued messages for connected clients.
     * 
     * This function retrieves queued destinations and messages from a log file 
     * and attempts to send those messages to the corresponding clients. For each 
     * queued destination, it checks if the client is connected by obtaining their 
     * socket file descriptor. If found, it constructs a framed SENDMSG message, 
     * sends it to the client, logs the action, and removes the message from the 
     * queued log. The function also records the sent message in the messages log 
     * with a status of "RELAYED".
     * 
     * @param clients A reference to a vector containing currently connected clients.
     * @param log_file A reference to an output file stream for logging sent messages.
     * @param msgs_log_file A reference to an output file stream for logging relayed messages.
     */

    std::fstream r_msgs_log_file("server_A_56_messages_log.txt", std::ios::in | std::ios::out);

    std::vector<std::string> queued_dests;
    std::vector<QueueEntry> queued_messages;

    get_queued_clients(r_msgs_log_file, clients, queued_dests);
    get_queued_messages(queued_messages, "");

    if (queued_dests.size() > 0){
        for (const auto dest: queued_dests){
            int sockfd;
            get_client_socket(clients, dest, sockfd);
            if (sockfd != 0){
                for (const auto entry : queued_messages){
                    if (entry.dest != dest) continue;
                    std::string framed_message;
                    framed_message.push_back(SOH);
                    framed_message += apply_escapes("SENDMSG," + entry.dest + "," + entry.source + "," + entry.message);
                    framed_message.push_back(EOT);
                    send(sockfd, framed_message.c_str(), framed_message.size(), 0);
                    log_file << "[" << get_timestamp() << "] Sent queued message to "
                            << "Group: " << dest
                            << " IP: " << entry.source
                            << ", Port: " << entry.message
                            << " - " << "SENDMSG," + entry.dest + "," + entry.source + "," + entry.message << std::endl;
                    remove_line_with_timestamp(entry.timestamp);
                    msgs_log_file << "[" << get_timestamp() << "];" << entry.dest << ";" << entry.source << ";" << entry.message << ";RELAYED" << std::endl;
                }
            }
        }
    }else{
        return;
    }
}

void relay_message(std::vector<std::string> arguments, std::vector<Client> &clients, std::string from_group_id, std::string my_group_id, std::ofstream &msgs_log_file, std::ofstream &log_file){
    /**
     * @brief Relays a message to the specified destination group.
     * SENDMSG,<TO GROUP ID>,<FROM GROUP ID>,<Message content>
     * This function processes a message relay request by determining the source 
     * and destination groups, and the message content. It first invokes 
     * `queueHandler` to handle any queued messages for connected clients. 
     * Depending on the number of arguments provided, it sets the source and 
     * destination group IDs and the message content accordingly. The function 
     * checks if the message exceeds a predefined limit and whether the destination 
     * group is the same as the current group, in which case it logs the message. 
     * If the destination group corresponds to a connected client, it sends the 
     * message directly. If the client is not connected, it marks the message as 
     * queued for future processing.
     * 
     * @param arguments A vector of strings representing the command arguments 
     *                  for the message relay.
     * @param clients A reference to a vector containing currently connected clients.
     * @param from_group_id The group ID from which the message is sent.
     * @param my_group_id The group ID of the current entity relaying the message.
     * @param msgs_log_file A reference to an output file stream for logging message 
     *                      statuses (RECEIVED, RELAYED, QUEUED).
     * @param log_file A reference to an output file stream for general logging 
     *                  of actions taken during message processing.
     */

    std::string source_group;
    std::string dest_group;
    std::string message;

    queueHandler(clients, log_file, msgs_log_file);
    
    if (arguments.size() == 3){
        source_group = my_group_id;
        dest_group = arguments[1];
        message = arguments[2];
    }else if (arguments.size() == 4){
        dest_group = arguments[1];
        source_group = arguments[2];
        message = arguments[3];
    }else{
        dest_group = arguments[1];
        source_group = arguments[2];
        for (int i = 3; i < arguments.size(); i++){
            message += arguments[i];
            if (i != arguments.size() - 1){
                message += ",";
            }
        }
    }

    // if message limit is reached, discard the message
    if (message.size() > MESSAGE_LIMIT){
        return;
    }

    // If the `<to group id>` corresponds to its own group (0-hop), the message is stored.
    if (dest_group == my_group_id){
        log_file << "[" << get_timestamp() << "] Stored message" << std::endl;   
        msgs_log_file << "[" << get_timestamp() << "];" << dest_group << ";" << source_group << ";" << message << ";RECEIVED" << std::endl;
        return;
    }

    // check if dest group is in the list of clients (1_HOP)
    bool connected_client;
    std::vector<Client>::iterator it;
    for (it = clients.begin(); it != clients.end(); ++it){
        if (it->id == dest_group){
            connected_client = true;
            break;
        }
    }
    if (connected_client == true){
        std::string framed_message;
        framed_message.push_back(SOH);
        framed_message += apply_escapes("SENDMSG," + dest_group + "," + source_group + "," + message);
        framed_message.push_back(EOT);
        send(it->sockfd, framed_message.c_str(), framed_message.size(), 0);
        msgs_log_file << "[" << get_timestamp() << "];" << dest_group << ";" << source_group << ";" << message << ";RELAYED" << std::endl;
        // if des_group is empty string
        if (dest_group.empty()){
            std::cout << "Empty dest group: " << dest_group << std::endl;
        }
        log_file << "[" << get_timestamp() << "] Sent message to "
                    << "Group: " << it->id
                    << " IP: " << it->ip
                    << ", Port: " << it->port
                    << " - " << "SENDMSG," + dest_group + "," + source_group + "," + message << std::endl;
        return;
    }else{
        // 2 HOPS
        msgs_log_file << "[" << get_timestamp() << "];" << dest_group << ";" << source_group << ";" << message << ";QUEUED" << std::endl;
        return;
    }

}

void queue_number_of_messages(std::map<std::string, int> &n_queued_messages){
    /**
     * @brief Counts the number of queued messages for each destination group.
     * 
     * This function reads a log file containing message entries and counts 
     * the number of messages that have a status of "QUEUED" for each destination 
     * group. It updates the provided map, where the keys are the destination 
     * group IDs and the values are the counts of queued messages for those 
     * groups. If a destination group is found for the first time, it initializes 
     * the count to 1; otherwise, it increments the existing count.
     * 
     * @param n_queued_messages A reference to a map that will store the number 
     *                          of queued messages for each destination group. 
     *                          The key is the destination group ID, and the 
     *                          value is the count of messages.
     */

    std::ifstream file("server_A_56_messages_log.txt");
    std::string line;
    while (std::getline(file, line)){
        std::stringstream ss(line);
        std::string timestamp, dest, src, message, status;

        std::getline(ss, timestamp, ';');
        std::getline(ss, dest, ';');
        std::getline(ss, src, ';');
        std::getline(ss, message, ';');
        std::getline(ss, status, ';');

        if (status == "QUEUED"){
            if (n_queued_messages.find(dest) == n_queued_messages.end()){
                n_queued_messages[dest] = 1;
            }else{
                n_queued_messages[dest] += 1;
            }
        }
    }
}

void keepaliveHandler(std::vector<Client> &clients, std::ofstream &log_file){
    /**
     * @brief Sends keepalive messages to connected clients with their queued message count.
     * 
     * This function generates and sends a keepalive message to each connected client, 
     * indicating the number of queued messages for that client. It first calls 
     * `queue_number_of_messages` to populate a map with the count of queued messages 
     * for each destination group. Then, for each client, it constructs a framed 
     * keepalive message, sends it over the client's socket, and logs the action, 
     * including the number of queued messages.
     * 
     * @param clients A reference to a vector containing currently connected clients.
     * @param log_file A reference to an output file stream for logging the sent 
     *                  keepalive messages and their details.
     */

    // for every connected clinet, send a keepalive message with the number of queued messages to them
    std::map<std::string, int> n_queued_messages;
    queue_number_of_messages(n_queued_messages);

    for (const auto client : clients){
        std::string framed_message;
        framed_message.push_back(SOH);
        framed_message += apply_escapes("KEEPALIVE," + std::to_string(n_queued_messages[client.id]));
        framed_message.push_back(EOT);
        send(client.sockfd, framed_message.c_str(), framed_message.size(), 0);
        log_file << "[" << get_timestamp() << "] Sent KEEPALIVE message to "
                    << "Group: " << client.id
                    << " IP: " << client.ip
                    << ", Port: " << client.port
                    << " - " << "KEEPALIVE," + std::to_string(n_queued_messages[client.id]) << std::endl;
    }
}

void statusHandler(Client client, std::vector<Client> clients, std::ofstream &log_file){
    /**
     * @brief Sends a status response message to a specified client.
     * 
     * This function constructs a status response that includes a comma-separated 
     * list of server IDs and the corresponding number of queued messages for each 
     * server. It first populates a map with the number of queued messages by 
     * calling `queue_number_of_messages`. Then, it builds the response message 
     * starting with "STATUSRESP" followed by pairs of server IDs and their message 
     * counts. The constructed message is framed, sent to the specified client, 
     * and the action is logged.
     * 
     * @param client A Client object representing the recipient of the status 
     *               response message.
     * @param clients A vector of currently connected clients (not used directly 
     *                in this function but may provide context).
     * @param log_file A reference to an output file stream for logging the sent 
     *                  STATUSRESP message and its details.
     */

    //Reply with comma separated list of servers and no. of messages you have for them
    // STATUSRESP,A54,20,A571,2
    std::map<std::string, int> n_queued_messages;
    queue_number_of_messages(n_queued_messages);

    std::string message = "STATUSRESP";
    // loop thorugh queued messages
    for (const auto entry : n_queued_messages){
        message += "," + entry.first + "," + std::to_string(entry.second);
    }

    std::string framed_message;
    framed_message.push_back(SOH);
    framed_message += apply_escapes(message);
    framed_message.push_back(EOT);

    send(client.sockfd, framed_message.c_str(), framed_message.size(), 0);
    log_file << "[" << get_timestamp() << "] Sent STATUSRESP message to "
                << "Group: " << client.id
                << " IP: " << client.ip
                << ", Port: " << client.port
                << " - " << message << std::endl;
}

void getmsgsHandler(std::vector<std::string> arguments, std::vector<Client>&clients, Client client, std::ofstream &log_file, int status){
    /**
     * @brief Handles the retrieval of queued messages for a specific group.
     * 
     * This function processes a request to get messages for a specified group ID. 
     * It checks the status to determine whether to send all queued messages or just 
     * the latest one. The function reads the queued messages from a log file, 
     * constructs the appropriate message(s) to send, and then sends them to the 
     * client. If the status indicates that multiple messages should be sent, 
     * all relevant messages are framed and sent. Otherwise, only the latest message 
     * is sent. Each action is logged for record-keeping.
     * 
     * @param arguments A vector of strings containing the command arguments. 
     *                  The second argument should be the group ID for which 
     *                  messages are being requested.
     * @param clients A reference to a vector of currently connected clients.
     * @param client A Client object representing the client requesting the messages.
     * @param log_file A reference to an output file stream for logging sent messages 
     *                  and responses.
     * @param status An integer indicating the status of the request: 
     *               1 for sending all queued messages and any other value for 
     *               sending only the latest message.
     */

    // getmsgs,<group_id>

    std::string dest_group = arguments[1];
    std::string from_group = client.id;
    // get queud messages for the dest group

    std::fstream r_msgs_log_file("server_A_56_messages_log.txt", std::ios::in | std::ios::out);

    std::vector<std::string> queued_dests;
    std::vector<QueueEntry> queued_messages;

    get_queued_clients(r_msgs_log_file, clients, queued_dests);
    get_queued_messages(queued_messages, dest_group);

    std::vector<std::string> messages_to_send;
    
    std::string message = "SENDMSG";
    for (const auto entry: queued_messages){
        message += "," + entry.dest + "," + entry.source + "," + entry.message;
        messages_to_send.push_back(message);
    }

    if (status == 1){
        for (const auto message: messages_to_send){
        std::string framed_message;
        framed_message.push_back(SOH);
        framed_message += apply_escapes(message);
        framed_message.push_back(EOT);
        if (send(client.sockfd, framed_message.c_str(), framed_message.size(), 0) < 0){
            std::cerr << "Send failed" << std::endl;
        }else{
            remove_line_with_timestamp(queued_messages[0].timestamp);
            log_file << "[" << get_timestamp() << "] [GETMSGS Response] Sent message to "
                    << "Group: " << client.id
                    << " IP: " << client.ip
                    << ", Port: " << client.port
                    << " - " << message << std::endl;
        }
    }
    }else{
        std::cout << "Sending latest message" << std::endl;
        // send the latest message only to the clinet
        std::string framed_message;
        framed_message.push_back(SOH);
        framed_message += apply_escapes(messages_to_send[0]);
        framed_message.push_back(EOT);
        if (send(client.sockfd, framed_message.c_str(), framed_message.size(), 0) < 0){
            std::cerr << "Send failed" << std::endl;
        }else{
            std:: cout << "Sent message to client" << std::endl;
            log_file << "[" << get_timestamp() << "] [GETMSG Response] Sent message to "
                    << "Group: " << client.id
                    << " IP: " << client.ip
                    << ", Port: " << client.port
                    << " - " << messages_to_send[0] << std::endl;
        }

    }
    
}


int main(int argc, char *argv[]) {
    int port = std::stoi(argv[1]);
    std::string my_ip = "130.208.246.249";
    std::string my_group_id = "A5_56";
    bool keep_running = true;

    std::ofstream log_file("server_A_56_log.txt", std::ios::app);
    if (!log_file.is_open()) {
        std::cerr << "Failed to open log file" << std::endl;
        return 1;
    }

    std::ofstream msgs_log_file("server_A_56_messages_log.txt", std::ios::app);
    if (!log_file.is_open()) {
        std::cerr << "Failed to open log file" << std::endl;
        return 1;
    }

    log_file << "****************************************************************" << std::endl;
    log_file << "Server started at " << get_timestamp() << std::endl;
    log_file << "****************************************************************" << std::endl;

    int server_sock;
    struct sockaddr_in server_addr;

    server_sock = socket(AF_INET, SOCK_STREAM, 0);

    if (server_sock < 0) {
        std::cerr << "Socket creation failed" << std::endl;
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(my_ip.c_str());
    server_addr.sin_port = htons(port);

    if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "Bind failed" << std::endl;
        exit(EXIT_FAILURE);
    }
   
    if (listen(server_sock, 3) < 0) {
        std::cerr << "Listen failed" << std::endl;
        exit(EXIT_FAILURE);
    }
    set_nonblocking(server_sock);


    std::cout << "Server listening on port " << port << std::endl;

    fd_set master_set, read_fds;
    FD_ZERO(&master_set);
    FD_ZERO(&read_fds);
    FD_SET(server_sock, &master_set);
    int max_sd = server_sock;

    std::vector<Client> clients;
    std::vector<Client> possible_clients;

    // connect to instructor 1
    std::string peer_ip = "130.208.246.249"; // Target peer IP
    connect_to_peer("Instr_1",peer_ip, 5001, my_group_id, clients, master_set, max_sd, log_file, 5);
    connect_to_peer("Instr_1",peer_ip, 5002, my_group_id, clients, master_set, max_sd, log_file, 5);
    connect_to_peer("Instr_1",peer_ip, 5003, my_group_id, clients, master_set, max_sd, log_file, 5);

    auto last_keepalive_time = std::chrono::steady_clock::now();
    const std::chrono::seconds keepalive_interval(60); // 60 seconds
    
    while (keep_running){
        read_fds = master_set;

        auto now = std::chrono::steady_clock::now();
        if (now - last_keepalive_time >= keepalive_interval) {
            keepaliveHandler(clients, log_file);
            last_keepalive_time = now; // Update the last keepalive time
        }

        int activity = select(max_sd + 1, &read_fds, nullptr, nullptr, nullptr);
        if (activity < 0 && errno != EINTR) {
            std::cerr << "Select error" << std::endl;
            break;
        }


        // Check for new connections
        if (FD_ISSET(server_sock, &read_fds) && clients.size() < MAX_PEERS) {
            struct sockaddr_in client_addr;
            socklen_t addr_len = sizeof(client_addr);

            int new_sock = accept(server_sock, (struct sockaddr *)&client_addr, &addr_len);
            if (new_sock < 0) continue;

            set_nonblocking(new_sock);
            std::string client_ip = inet_ntoa(client_addr.sin_addr);
            int client_port = ntohs(client_addr.sin_port);

            Client new_client;
            new_client.id = ""; // Will be set later
            new_client.ip = client_ip;
            new_client.port = client_port;
            new_client.sockfd = new_sock;
            clients.push_back(new_client);
            std::printf("New connection from %s:%d\n", client_ip.c_str(), client_port);

            // Identift the server to the client
            std::string framed_message;
            framed_message.push_back(SOH);
            framed_message += apply_escapes("HELO," + my_group_id);
            framed_message.push_back(EOT);
            send(new_client.sockfd, framed_message.c_str(), framed_message.size(), 0);
            log_file << "[" << get_timestamp() << "] Sent message to "
                    << "Group: " << new_client.id
                    << " IP: " << new_client.ip
                    << ", Port: " << new_client.port
                    << " - " << "HELO," + my_group_id << std::endl;


            // Add the new socket to the master set
            FD_SET(new_sock, &master_set);
            if (new_sock > max_sd) max_sd = new_sock;
        }

        // check for IO operations on existing clients
        for (size_t i = 0; i < clients.size(); ++i){
            int client_sock = clients[i].sockfd;

            if (FD_ISSET(client_sock, &read_fds)) {
                char buffer[BUFFER_SIZE];
                memset(buffer, 0, sizeof(buffer));

                ssize_t bytes_received = recv(client_sock, buffer, sizeof(buffer), 0);
                
                if (bytes_received <= 0){
                    // handle client dissconnection
                    if (bytes_received == 0){
                        std::string timestamp = get_timestamp();
                        log_file << "[" << timestamp << "] Client disconnected "
                                    << "Group: " << clients[i].id
                                    << " IP: " << clients[i].ip
                                    << ", Port: " << clients[i].port << std::endl;

                    }else{
                        // std::cerr << "Recv failed" << std::endl;

                        continue;
                    }
                    close(client_sock);
                    FD_CLR(client_sock, &master_set);
                    clients.erase(clients.begin() + i);
                    i--;
                }else{
                    // handle incoming message
                    std::vector<std::string> arguments;
                    std::string message = message_handler(bytes_received, buffer);

                    message_parser(message, arguments);
                    if (arguments.size() == 0){
                        // std::cerr << "Invalid message" << std::endl;
                        continue;
                    }
                    std::string command = arguments[0];

                    // if client doesnt identify himself with his group id, disconnect him
                    log_file << "[" << get_timestamp() << "] New message from "
                                    << "Group: " << clients[i].id
                                    << " IP: " << clients[i].ip
                                    << ", Port: " << clients[i].port
                                    << " - " << message << std::endl;
                    
                    if (clients[i].id.empty()){
                        if (command == "HELO"){
                            clients[i].id = arguments[1];
                            std::string client_id = clients[i].id;

                            // if client ID does not start with Instr_ or does not start with A5_, disconnect him
                            if (client_id.compare(0, 6, "Instr_") != 0 && client_id.compare(0, 3, "A5_") != 0) {
                                std::cout << "Client : " << client_id << " disconnected" << std::endl;
                                log_file << "[" << get_timestamp() << "] Unidentified client disconnected" << std::endl;
                                close(client_sock);
                                FD_CLR(client_sock, &master_set);
                                clients.erase(clients.begin() + i);
                                continue;
                            }

                            // reply with servers
                            std::string server_string = create_server_string(my_group_id, my_ip, port, clients);
                            std::string framed_message;
                            framed_message.push_back(SOH);
                            framed_message += apply_escapes(server_string);
                            framed_message.push_back(EOT);
                            send(client_sock, framed_message.c_str(), framed_message.size(), 0);
                            log_file << "[" << get_timestamp() << "] Sent message to "
                                    << "Group: " << clients[i].id
                                    << " IP: " << clients[i].ip
                                    << ", Port: " << clients[i].port
                                    << " - " << server_string << std::endl;
                           
                        }else{
                            if (clients[i].port == 5001){
                                clients[i].id = "Instr_1";
                            }else if (clients[i].port == 5002){
                                clients[i].id = "Instr_2";
                            }else if (clients[i].port == 5003){
                                clients[i].id = "Instr_3";
                            }else{
                                log_file << "[" << get_timestamp() << " Unidentified client disconnected" << std::endl;

                                close(client_sock);
                                FD_CLR(client_sock, &master_set);
                                clients.erase(clients.begin() + i);
                                continue;
                            }
                        }
                    }

                    if (command == "SERVERS"){ 
                        std::string to_process = message.substr(8);
                        std::regex pattern(R"((\w+),([\d.]+),(-?\d+))");
                        std::sregex_iterator iter(to_process.begin(), to_process.end(), pattern);
                        std::sregex_iterator end;

                        while (iter != end){
                            std::smatch match = *iter;
                            std::string name = match[1].str();
                            std::string ip = match[2].str();
                            std::string port = match[3].str();
                            
                            if (name != my_group_id && port != "5001" && port != "5002" && port != "5003"){
                                if (clients.size() < MAX_PEERS) connect_to_peer(name, ip, std::stoi(port), my_group_id, clients, master_set, max_sd, log_file, 5);
                            }
                            ++iter;
                        }

                    }

                    if (command == "LISTSERVERS"){
                        std::string server_string = create_server_string(my_group_id, my_ip, port, clients);
                        std::string framed_message;
                        framed_message.push_back(SOH);
                        framed_message += apply_escapes(server_string);
                        framed_message.push_back(EOT);
                        send(client_sock, framed_message.c_str(), framed_message.size(), 0);
                        log_file << "[" << get_timestamp() << "] Sent message to "
                                << "Group: " << clients[i].id
                                << " IP: " << clients[i].ip
                                << ", Port: " << clients[i].port
                                << " - " << server_string << std::endl;
                    }

                    if (command == "SENDMSG"){
                        relay_message(arguments, clients, my_group_id, my_group_id, msgs_log_file, log_file);
                    }

                    if (command == "GETMSGS"){
                        getmsgsHandler(arguments, clients, clients[i], log_file, 1); // 1 indicates that the message is from a server so we can send all the messages for a group id.
                    }
                    if (command == "GETMSG"){
                        getmsgsHandler(arguments, clients, clients[i], log_file, 0); // 0 indicates that the message is from the client so we can send only one message accroding to the protocol.
                    }

                    if (command == "STATUSREQ"){
                        statusHandler(clients[i], clients, log_file);
                    }

                    // handle other commands.
                    if (std::find(COMMANDS.begin(), COMMANDS.end(), command) == COMMANDS.end()){
                        log_file << "[" << get_timestamp() << "] Invalid command from "
                                    << "Group: " << clients[i].id
                                    << " IP: " << clients[i].ip
                                    << ", Port: " << clients[i].port
                                    << " - " << message << std::endl;
                        continue;
                    }            

                }
            }
        }
    }
    close(server_sock);
    return 1;
}