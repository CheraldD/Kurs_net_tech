/** @file
 * @author Солдатенков А.Д.
 * @version 1.0
 * @date 23.02.2025
 * @copyright ИБСТ ПГУ
 * @brief Исполняемый файл модуля client
 */
#include "client.h"
void client::work(UI &intf)
{
    // user_data_location=intf.get_user_data_location();
    serv_ip = intf.get_serv_ip().c_str();
    port = intf.get_port();
    std::cout << "Начало работы клиента" << std::endl;
    start();
    // read_user_data_file(user_data_location);
    connect_to_server();
    files = recv_vector();
    print_vector(files);
    std::chrono::milliseconds duration(1);
    std::this_thread::sleep_for(duration);
    std::string file_path = "data.txt";
    std::string path = "test.txt";
    send(sock, file_path.c_str(), file_path.length(), 0);
    recv_file(path);
    // client_auth();
}
void client::start()
{
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
    {
        debugger.show_error_information("Ошибка в start()", "Возможная причина - неверные параметры socket()", "Синтаксическая ошибка");
    }
    std::cout << "Сокет создан" << std::endl;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    inet_pton(AF_INET, serv_ip, &serverAddr.sin_addr);
}
void client::connect_to_server()
{
    if (connect(sock, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0)
    {
        close_sock();
        debugger.show_error_information("Ошибка в connect_to_server()", "Возможная причина - неверный айпи или порт сервера", "Логическая ошибка");
    }
    std::cout << "Клиент соединился с сервером" << std::endl;
    send_data("shkaf");
}
std::string client::recv_data()
{
    int rc = 0;
    while (true)
    {
        buffer = std::unique_ptr<char[]>(new char[buflen]);
        rc = recv(sock, buffer.get(), buflen, MSG_PEEK);
        if (rc == 0)
        {
            close_sock();
            debugger.show_error_information("Ошибка в recv_data()", "Принято 0 байт от сервера", "Логическая ошибка");
        }
        else if (rc < 0)
        {
            debugger.show_error_information("Ошибка в recv_data()", "Результат recv = -1", "Логическая ошибка");
        }
        if (rc < buflen)
            break;
        buflen *= 2;
    }
    std::string msg(buffer.get(), rc);
    recv(sock, nullptr, rc, MSG_TRUNC);
    return msg;
    std::cout << "Данные от сервера приняты" << std::endl;
}

void client::close_sock()
{
    close(sock);
    std::cout << "Сокет клиента закрыт" << std::endl;
}
void client::send_data(std::string data)
{
    std::unique_ptr<char[]> temp{new char[data.length() + 1]};
    strcpy(temp.get(), data.c_str());
    buffer = std::move(temp);
    int sb = send(sock, buffer.get(), data.length(), 0);
    if (sb < 0)
    {
        close_sock();
        debugger.show_error_information("Ошибка в send_data() - string", "Результат send = -1", "Логическая ошибка");
    }
    std::cout << "Отправлены данные строкового типа" << std::endl;
}
std::vector<std::string> client::recv_vector() {
    std::vector<std::string> received_vector;
    
    // Получаем размер вектора
    uint32_t vec_size = 0;
    if (recv(sock, &vec_size, sizeof(vec_size), 0) <= 0) {
        std::cerr << "Ошибка при получении размера вектора" << std::endl;
        close_sock();
        return received_vector;
    }
    vec_size = ntohl(vec_size); // Преобразуем порядок байтов

    // Получаем строки
    for (uint32_t i = 0; i < vec_size; ++i) {
        uint32_t str_size = 0;

        // Получаем размер строки
        if (recv(sock, &str_size, sizeof(str_size), 0) <= 0) {
            std::cerr << "Ошибка при получении размера строки" << std::endl;
            close_sock();
            return received_vector;
        }
        str_size = ntohl(str_size);

        // Получаем саму строку
        std::unique_ptr<char[]> buffer(new char[str_size + 1]);
        if (recv(sock, buffer.get(), str_size, 0) <= 0) {
            std::cerr << "Ошибка при получении строки" << std::endl;
            close_sock();
            return received_vector;
        }
        buffer[str_size] = '\0';

        received_vector.emplace_back(buffer.get());
    }
    
    return received_vector;
}


void client::print_vector(const std::vector<std::string> &vec)
{
    std::cout << "Список файлов:" << std::endl;
    for (const auto &file : vec)
    {
        std::cout << file << std::endl;
    }
}
void client::recv_file(std::string &file_path)
{
    std::ofstream file(file_path, std::ios::binary);
    if (!file)
    {
        std::cerr << "Ошибка открытия файла для записи!" << std::endl;
        return;
    }

    uint64_t buffer;
    ssize_t bytes_received;
    while ((bytes_received = recv(sock, &buffer, sizeof(buffer), 0)) > 0)
    {
        if (buffer == 0)
            break; // Проверка на конец файла
        file.write(reinterpret_cast<char *>(&buffer), bytes_received);
    }

    file.close();
    std::cout << "Файл успешно принят!" << std::endl;
}