/** @file
* @author Стригин А.В.
* @version 1.0
* @date 23.12.2023
* @copyright ИБСТ ПГУ
* @brief Заголовочный файл для модуля error
*/
#pragma once
#include <stdexcept>
#include <string>
/** @brief Класс ошибок
* @details Используется для отлова специфических ошибок, возникающих в ходе работы модулей
* В конструкторе указывается строка с сообщением ошибки
*/
class critical_error:public std::runtime_error{
    public:
    /** @brief Конструктор ошибки
    * @param [in] s Сообщение об ошибке
    */
    critical_error(const std::string& s):std::runtime_error(s){}
};