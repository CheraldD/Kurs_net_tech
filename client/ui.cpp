/** @file
* @author Солдатенков А.Д.
* @version 1.0
* @date 23.02.2025
* @copyright ИБСТ ПГУ
* @brief Исполняемый файл модуля UI
*/
#include "ui.h"
#include <boost/program_options.hpp>
namespace po = boost::program_options;
UI::UI(int argc, char *argv[])
{

    desc.add_options()
    ("help,h", "Помощь\nВсе параметры ниже являются обязательными")
    ("serv_ip,s", po::value<std::vector<std::string>>()->multitoken(), "Айпи сервера")
    ("operation, o",po::value<std::vector<uint>>()->multitoken(), "1 - аутентификация, 0 - регистрация")
    ("username, u",po::value<std::vector<std::string>>()->multitoken(), "Имя пользователя")
    ("password, pa",po::value<std::vector<std::string>>()->multitoken(), "Пароль пользователя")
    ("port,p", po::value<std::vector<uint>>()->multitoken(), "Порт сервера");
    //("in_file,i", po::value<std::vector<std::string>>()->multitoken(), "Файл с входными данными")
    //("out_file,o", po::value<std::vector<std::string>>()->multitoken(), "Файл с результатом")
    ///("user_data,u", po::value<std::vector<std::string>>()->multitoken(), "Файл с персональными данными пользователя(логин, пароль)");

    po::store(po::parse_command_line(argc, argv, desc), vm);

    if (vm.count("help") or !vm.count("serv_ip") or !vm.count("port")) {
        std::cout << desc << std::endl;
        exit(0);
    }

    po::notify(vm);
}
std::string UI::get_password(){
    if (vm.count("password") and !vm["password"].as<std::vector<std::string>>().empty())
    {
        const std::vector<std::string> &password = vm["password"].as<std::vector<std::string>>();
        return password.back();
    }
    else
    {
        std::cout << desc << std::endl;
        debugger.show_error_information("Ошибка в get_password()", "Неопределенное значение пароля", "Неопределенная ошибка");
        return "";
    }
}
std::string UI::get_username(){
    if (vm.count("username") and !vm["username"].as<std::vector<std::string>>().empty())
    {
        const std::vector<std::string> &username = vm["username"].as<std::vector<std::string>>();
        return username.back();
    }
    else
    {
        std::cout << desc << std::endl;
        debugger.show_error_information("Ошибка в get_password()", "Неопределенное значение пароля", "Неопределенная ошибка");
        return "";
    }
}
uint UI::get_op(){
    if (vm.count("operation") and !vm["operation"].as<std::vector<uint>>().empty())
    {
        const std::vector<uint> &op = vm["operation"].as<std::vector<uint>>();
        if (op.back()>1 or op.back()<0)
        {
            std::cout << desc << std::endl;
            debugger.show_error_information("Ошибка в get_op()", "Неверный номер операции", "Логическая ошибка");
            return 2;
        }
        return op.back();
    }
    else
    {
        std::cout << desc << std::endl;
        debugger.show_error_information("Ошибка в get_op()", "Неопределенное значение операции", "Неопределенная ошибка");
        return 2;
    }
}
uint UI::get_port()
{
    if (vm.count("port") and !vm["port"].as<std::vector<uint>>().empty())
    {
        const std::vector<uint> &ports = vm["port"].as<std::vector<uint>>();
        if (ports.back() < 1024)
        {
            std::cout << desc << std::endl;
            debugger.show_error_information("Ошибка в get_port()", "Выбранный порт меньше 1024", "Логическая ошибка");
            return 1;
        }
        if (ports.back() > 65535)
        {
            std::cout << desc << std::endl;
            debugger.show_error_information("Ошибка в get_port()", "Выбранный порт больше 65535", "Логическая ошибка");
            return 1;
        }
        return ports.back();
    }
    else
    {
        std::cout << desc << std::endl;
        debugger.show_error_information("Ошибка в get_port()", "Неопределенное значение порта", "Неопределенная ошибка");
        return 1;
    }
}
std::string UI::get_serv_ip()
{
    struct in_addr addr;
    if (vm.count("serv_ip") and !vm["serv_ip"].as<std::vector<std::string>>().empty())
    {
        const std::vector<std::string> &ip_s = vm["serv_ip"].as<std::vector<std::string>>();
        if (inet_pton(AF_INET, ip_s.back().c_str(), &addr) == 0)
        {
            std::cout << desc << std::endl;
            debugger.show_error_information("Ошибка в get_ip()", "ip не соответстует формату ipv4", "Логическая ошибка");
            return "";
        }
        return ip_s.back();
    }
    else
    {
        std::cout << desc << std::endl;
        debugger.show_error_information("Ошибка в get_ip()", "Неопределенное значение ip", "Неопределенная ошибка");
        return "";
    }
}

std::string UI::check_path(std::string path, std::string function)
{
    boost::filesystem::path filePath(path);
    if (path.empty())
    {
        std::cout << desc << std::endl;
        debugger.show_error_information(function, "Пустой путь к файлу", "Ошибка синтаксиса");
        return "";
    }
    if (!boost::filesystem::exists(filePath))
    {
        std::cout << desc << std::endl;
        debugger.show_error_information(function, "Файла не существует", "Ошибка синтаксиса");
        return "";
    }
    if (boost::filesystem::is_directory(filePath))
    {
        std::cout << desc << std::endl;
        debugger.show_error_information(function, "Путь указывает на папку", "Ошибка синтаксиса");
        return "";
    }
    if (!(boost::filesystem::status(filePath).permissions() & boost::filesystem::perms::owner_read))
    {
        std::cout << desc << std::endl;
        debugger.show_error_information(function, "Нет прав на чтение файла", "Ошибка доступа");
        return "";
    }
    if (boost::filesystem::is_symlink(filePath))
    {
        std::cout << desc << std::endl;
        debugger.show_error_information(function, "Путь указывает ссылку", "Логическая ошибка");
        return "";
    }
    return boost::filesystem::absolute(filePath).string();
}