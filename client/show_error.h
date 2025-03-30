/** @file
* @author Солдатенков А.Д.
* @version 1.0
* @date 23.02.2025
* @copyright ИБСТ ПГУ
* @brief Заголовочный файл модуля show_error
*/
#pragma once
#include <vector>
#include <string>
#include <fstream>
#include <iostream>
#include <chrono>
#include <cstring>
#include <stdexcept>
/**
 * @class client_error
 * @brief Класс исключений для ошибок клиента.
 * 
 * Этот класс наследует `std::runtime_error` и используется для представления ошибок,
 * связанных с работой клиента, с возможностью передачи подробного сообщения об возникшей ошибке.
 */
class client_error : public std::runtime_error {
    public:
        /**
         * @brief Конструктор ошибки.
         * 
         * Конструктор инициализирует объект ошибки с заданным сообщением.
         * 
         * @param s Сообщение об ошибке.
         */
        client_error(const std::string& s) : std::runtime_error(s) {}
};

/**
 * @class show_error
 * @brief Класс для обработки и вывода информации об ошибках.
 * 
 * Класс предоставляет метод для генерации исключений и вывода информации о возникающих
 * ошибках в ходе работы клиента.
 */
class show_error {
    public:
        /**
         * @brief Отображение информации об ошибке.
         * 
         * Этот метод генерирует исключение `client_error`, содержащее информацию о
         * возникшей ошибке, включая функцию, данные и тип ошибки.
         * 
         * @param function Название функции, в которой произошла ошибка.
         * @param data Дополнительные данные о контексте ошибки.
         * @param type Тип ошибки.
         * 
         * @return Всегда возвращает 0, так как метод генерирует исключение.
         */
        int show_error_information(std::string function, std::string data, std::string type);
};