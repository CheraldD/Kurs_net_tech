#include "ui.h"
#include <boost/program_options.hpp>
namespace po = boost::program_options;
UI::UI(int argc, char* argv[]) {
    // Добавление опций командной строки
    desc.add_options()
        ("help,h", "Помощь")  // Опция для вывода справки
        ("Log_loc,l", po::value<std::vector<std::string>>()->multitoken(), "Путь для log файла")  // Опция для указания пути к лог-файлу
        ("Port,p", po::value<std::vector<uint>>()->multitoken(), "Порт сервера");  // Опция для указания портов сервера

    try {
        // Парсинг командной строки
        po::store(po::parse_command_line(argc, argv, desc), vm);

        // Если указана опция "help" или отсутствуют обязательные параметры ("Log_loc" или "Port"), выводим справку и завершаем программу
        if (vm.count("help") || !vm.count("Log_loc") || !vm.count("Port")) {
            std::cout << desc << std::endl;
            exit(0);  // Выход из программы, если не все параметры указаны
        }

        // Применяем опции, если парсинг прошел успешно
        po::notify(vm);
    } catch (po::error& e) {
        // Обработка ошибок парсинга опций
        std::cout << e.what() << std::endl;
    }
    catch(critical_error &e){
        // Обработка критических ошибок
        std::cout << "Критическая ошибка: " << e.what() << std::endl;
    }
}
uint UI::get_port() {
    // Проверка, была ли указана опция "Port"
    if (vm.count("Port")) {
        const std::vector<uint>& ports = vm["Port"].as<std::vector<uint>>();  // Извлекаем список портов

        // Если порт меньше 1024, выбрасываем ошибку, так как порты с таким значением считаются системными
        if (ports.back() < 1024) {
            log.write_log(log_loc, "Работа модуля: UI. Пользователь ввел системный порт");
            throw critical_error("Выбран системный порт");
        }

        return ports.back();  // Возвращаем последний указанный порт
    } else {
        return 1;  // Если порт не указан, возвращаем дефолтное значение 1
    }
}

std::string UI::get_log_loc() {
    // Проверка, была ли указана опция "Log_loc"
    if (vm.count("Log_loc")) {
        const std::vector<std::string>& log_loc = vm["Log_loc"].as<std::vector<std::string>>();  // Извлекаем путь к лог-файлу
        return log_loc.back();  // Возвращаем последний указанный путь
    } else {
        return "";  // Если путь не указан, возвращаем пустую строку
    }
}
