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
#include "logger.h"
#include "error.h"
#include "data_handler.h"
#include <cryptopp/cryptlib.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <cryptopp/md5.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>

class communicator
{    
private:
    struct sockaddr_in serverAddr, clientAddr;
    socklen_t addr_size;
    std::string base_location;
    size_t buflen = 1024;
    std::unique_ptr<char[]> buffer{new char[buflen]};
    uint p;
    std::string digits[16] = {"0","1","2","3","4","5","6","7","8","9","A","B","C","D","E","F"};

public:
    int serverSocket, clientSocket;
    logger log;
    std::string cl_id,log_location;
    
    void connect_to_cl();
    void send_data(std::string data, std::string msg);
    std::string recv_data(std::string messg);
    void close_sock();
    void start();
    void send_file_list();
    void send_file(std::string& file_path);
    communicator(uint port, std::string base_loc, std::string log_loc);
};
