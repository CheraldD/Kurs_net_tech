/** @file
* @author Стригин А.В.
* @version 1.0
* @date 23.12.2023
* @copyright ИБСТ ПГУ
* @brief Исполняемый файл для модуля data_handler
*/
#include "data_handler.h"
/*data_handler::data_handler(std::string log){
    
    
}*/
std::vector<std::string> data_handler::get_file_list() {
    std::vector<std::string> file_list;
    std::string exe_path = std::filesystem::current_path().string();
    
    for (const auto& entry : std::filesystem::directory_iterator(exe_path)) {
        if (entry.is_regular_file()) {
            file_list.push_back(entry.path().filename().string());
        }
    }
    return file_list;
}
