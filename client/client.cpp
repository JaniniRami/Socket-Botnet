#include <iostream>
#include <string>
#include <cstring>
#include <arpa/inet.h>
#include <unistd.h>
#include <thread>
#include <sys/socket.h>
#include <netinet/in.h>

#define BUFFER_SIZE 1024
#define SOH 0x01 // Start of message (ASCII 0x01)
#define EOT 0x04 // End of message (ASCII 0x04)
#define ESC 0x1B // Escape character for bytestuffing

// Function to escape SOH, EOT, and ESC characters in the message
std::string apply_escapes(const std::string &message) {
    std::string escaped_message;
    for (char ch : message) {
        if (ch == SOH || ch == EOT || ch == ESC) {
            escaped_message.push_back(ESC); // Add escape character
        }
        escaped_message.push_back(ch);
    }
    return escaped_message;
}

// Function to send a framed message to the server
void send_message(int server_fd, const std::string &message) {
    std::string framed_message;
    
    // Add SOH (Start of Header) and EOT (End of Transmission)
    framed_message.push_back(SOH);
    framed_message += apply_escapes(message); // Apply bytestuffing
    framed_message.push_back(EOT);
    // Send the framed message
    if (send(server_fd, framed_message.c_str(), framed_message.length(), 0) < 0) {
        std::cerr << "Send failed" << std::endl;
    }
}

std::string remove_escapes(const std::string &message) {
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


std::string receive_response(int recv_sock) {
    char recv_buffer[BUFFER_SIZE];
    

    ssize_t bytes_received = recv(recv_sock, recv_buffer, sizeof(recv_buffer) - 1, 0);
    if (bytes_received < 0) {
        std::cerr << "Receive failed" << std::endl;
        return "";
    }else{
        std::cout << "Received: " << recv_buffer << std::endl;
    }

    while (true){
        if (bytes_received < 0){
            std::cerr << "Receive failed" << std::endl;
            return "";
        }else{
            std::string message_buffer;
            bool receiving_message = false;

            for (ssize_t i=0; i<bytes_received; i++){
                char byte = recv_buffer[i];
                if (byte == SOH){
                    message_buffer.clear();
                    receiving_message = true;
                }else if (byte == EOT){
                    receiving_message = false;

                    std::string message = remove_escapes(message_buffer);
                    // clear buffer
                    memset(recv_buffer, 0, sizeof(recv_buffer));
                    return message;
                }
            }
        }
    }

}

void listen_for_messages(int recv_sock) {
    while (true) {
        std::string framed_message = receive_response(recv_sock);
        // if message starts with KEEPALIVE, ignore it
        if (framed_message.find("KEEPALIVE") != std::string::npos){
            continue;
        }else{
            if (framed_message == "") continue;
            std::cout << "Recieved: " <<  framed_message << std::endl;
        }
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <port>" << std::endl;
        return 1;
    }

    int port = std::stoi(argv[1]);
    std::string id = "A3_56";  // Your client ID
    const char *server_ip = "130.208.246.249"; // Your server IP

    // Setup the socket and connect to the server
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        std::cerr << "Socket creation failed" << std::endl;
        return 1;
    }

    int optval = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
        std::cerr << "Setsockopt failed" << std::endl;
        return 1;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, '0', sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
        std::cerr << "Invalid address" << std::endl;
        return 1;
    }

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "Connection failed" << std::endl;
        return 1;
    }

    send_message(sock, "HELO,A5_CLIENT"); // identify the client
    
    // Start the thread to listen for messages from the server
    std::thread recv_thread(listen_for_messages, sock);
    recv_thread.detach();

    sleep(1);
    // Send an initial HELO message


    // Main loop to handle client commands
    while (true) {
        std::cout << "**************** Command Selection ****************" << std::endl;
        std::cout << "Please select a command:" << std::endl;
        std::cout << "1. LISTSERVERS" << std::endl;
        std::cout << "2. SENDMSG" << std::endl;
        std::cout << "3. GETMSG" << std::endl;
        std::cout << "ENTER COMMAND NUMBER: ";
        
        int choice;
        std::cin >> choice;
        std::cin.ignore();  // To ignore newline left in buffer

        std::string client_command;
        std::string group_id, message_contents;
        if (choice != 1 && choice != 2 && choice != 3) {
            std::cerr << "Invalid choice, please try again." << std::endl;
            break;
        }
        switch (choice) {
            case 1:
                // Handle LISTSERVERS
                client_command = "LISTSERVERS";
                break;

            case 2:
                // Handle SENDMSG
                std::cout << "Enter Group ID: ";
                std::getline(std::cin, group_id);
                std::cout << "Enter Message: ";
                std::getline(std::cin, message_contents);
                client_command = "SENDMSG," + group_id + "," + message_contents;
                break;

            case 3:
                // Handle GETMSG
                std::cout << "Enter Group ID: ";
                std::getline(std::cin, group_id);
                client_command = "GETMSG," + group_id;
                break;

            default:
                std::cerr << "Invalid choice, please try again." << std::endl;
                break;
        }

        // Send the constructed command to the server
        send_message(sock, client_command);
    }

    close(sock);
    return 0;
}
