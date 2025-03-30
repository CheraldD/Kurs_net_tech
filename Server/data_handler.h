#pragma once
#include <string>
#include <vector>
#include <memory>
#include "logger.h"
#include <filesystem>
class data_handler {
private:
    uint32_t nums;

public:
    logger log;
    std::string log_location;
    std::vector<std::string> get_file_list();    
    //data_handler(std::string log);
};