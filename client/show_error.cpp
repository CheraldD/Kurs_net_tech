/** @file
* @author Солдатенков А.Д.
* @version 1.0
* @date 23.02.2025
* @copyright ИБСТ ПГУ
* @brief Исполняемый файл модуля show_error
*/
#include "show_error.h"
int show_error::show_error_information(std::string function,std::string data,std::string type){
    throw client_error(function+" / "+data+" / "+type);
    return 0;
}
