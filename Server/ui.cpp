/** @file
* @author Стригин А.В.
* @version 1.0
* @date 23.12.2023
* @copyright ИБСТ ПГУ
* @brief Исполняемый файл для модуля ui
*/
#include "ui.h"
#include <boost/program_options.hpp>
namespace po = boost::program_options;
UI::UI(int argc, char* argv[])
{
    desc.add_options()
    ("help,h", "Помощь")
    ("Log_loc,l", po::value<std::vector<std::string>>()->multitoken(), "Путь для log файла")
    ("Port,p", po::value<std::vector<uint>>()->multitoken(), "Порт сервера");
    try {
        po::store(po::parse_command_line(argc, argv, desc), vm);
        if (vm.count("help") or !vm.count("Log_loc") or !vm.count("Port")) {
            std::cout << desc << std::endl;
            exit(0);
        }
        po::notify(vm);
    } catch (po::error& e) {
        std::cout << e.what() << std::endl;
    }
    catch(critical_error &e){
        std::cout<<"Критическая ошибка: "<<e.what()<<std::endl;
    }
}
uint UI::get_port()
{
    if (vm.count("Port")) {
        const std::vector<uint>& ports = vm["Port"].as<std::vector<uint>>();
        if(ports.back()<1024){
            log.write_log(log_loc,"Работа модуля: UI. Пользователь ввел системный порт");
            throw critical_error("Выбран системный порт");
            
        }
        return ports.back();
    } else {
        return 1;
    }
}
std::string UI::get_log_loc()
{
    if (vm.count("Log_loc")) {
        const std::vector<std::string>& log_loc = vm["Log_loc"].as<std::vector<std::string>>();
        return log_loc.back();
    } else {
        return "";
    }
}