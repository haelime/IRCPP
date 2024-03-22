#include <iostream>
#include <string>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

int main() {
    // 서버 주소와 포트 설정
    std::string server_address = "127.0.0.1"; // 서버 IP 주소
    int server_port = 6667; // 서버 포트 번호

    // 소켓 생성
    int client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket == -1) {
        std::cerr << "Error: Could not create socket\n";
        return 1;
    }

    // 서버에 연결할 주소 설정
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);
    if (inet_pton(AF_INET, server_address.c_str(), &server_addr.sin_addr) <= 0) {
        std::cerr << "Error: Invalid address/Address not supported\n";
        return 1;
    }

    // 서버에 연결
    std::cout << "Connecting to server...\n";
    if (connect(client_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "Error: Connection failed\n";
        return 1;
    }
    std::cout << "Connected to server\n";

    // 서버에 IRC 메시지 보내기
    std::string message = "NICK test\r\nUSER test 0 * :test\r\nJOIN #test\r\nPRIVMSG #test :Hello, world!\r\nQUIT\r\n";

    if (send(client_socket, message.c_str(), message.length(), 0) != static_cast<ssize_t> (message.length())) {
        std::cerr << "Error: Send failed\n";
        return 1;
    }
    std::cout << "Message sent to server: " << message << std::endl;


    // 서버로부터 응답 받기
    char buffer[1024] = {0};
    int valread = read(client_socket, buffer, 1024);
    if (valread < 0) {
        std::cerr << "Error: Read failed\n";
        return 1;
    }
    std::cout << "Message from server: " << buffer << std::endl;

    // 소켓 닫기
    close(client_socket);

    return 0;
}