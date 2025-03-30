#pragma once
#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <algorithm>
#include <memory>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <random>
#include <chrono>
#include <thread>
#include <limits>
#include "show_error.h"
#include "ui.h"
#include <cryptopp/cryptlib.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <cryptopp/md5.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>

class client {
    private:
        show_error debugger;
        std::string user_data_location;
        std::string hash;
        std::string password;
        std::string salt;
        std::string id;
        struct sockaddr_in serverAddr;
        socklen_t addr_size;
        size_t buflen = 1024;
        std::unique_ptr<char[]> buffer{new char[buflen]};
        uint port;
        std::ifstream u_data;

        void read_user_data_file(std::string location);

    public:
        const char* serv_ip;
        int sock;
        std::vector <std::string> files;
        void connect_to_server();
        void send_data(std::string data);
        std::string recv_data();
        void close_sock();
        void start();
        void work(UI &intf);

        std::vector<std::string> recv_vector();
        void print_vector(const std::vector<std::string>& vec);
        void recv_file(std::string& file_path);
};