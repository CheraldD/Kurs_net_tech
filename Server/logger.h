/** @file
* @author Стригин А.В.
* @version 1.0
* @date 23.12.2023
* @copyright ИБСТ ПГУ
* @brief Заголовочный файл для модуля logger
*/
#pragma once
#include <vector>
#include <string>
#include <fstream>
#include <iostream>
#include <chrono>
#include <cstring>
#include "error.h"
#include <mutex>
#include <boost/filesystem.hpp>
/** @brief Класс логгера
* @details Запись сообщений в лог файла осуществляетс в методе write_log
* Отсутствует конструктор
*/
class logger{
    public:
    /** @brief Объект ofstream для открытия файла для записи
    */
    std::ofstream log;
    /**
    * @brief Метод записи сообщения в лог файл
    * @details С помощью библиотеки chrono получается текущее время, затем записывается сообщение в файл 
    * в формате время/сообщение. В начале сеанса записи файл открывается, в конце закрывается
    * @param [in] log_loc Расположение лог файла
    * @param [in] message Сообщение для записи в лог файл
    * @throw critical_error, если log_loc указывает путь к несуществующему файлу
    */
    std::mutex mtx;
    int write_log(std::string log_loc,std::string message);
};