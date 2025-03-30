/** @file
 * @author Стригин А.В.
 * @version 1.0
 * @date 23.12.2023
 * @copyright ИБСТ ПГУ
 * @brief Исполняемый файл для модуля communicator*/
#include "communicator.h"

void communicator::connect_to_cl()
{
    if (listen(serverSocket, 10) == 0)
    {
        std::cout << "Сервер слушает..." << std::endl;
        log.write_log(log_location, "Работа модуля: communicator. Сервер встал на прослушку порта");
    }
    else
    {
        log.write_log(log_location, "Работа модуля: communicator. Ошибка при прослушивании порта");
        std::cout << "Ошибка при прослушивании" << std::endl;
        throw critical_error("Север не встал на прослушку порта");
    }
    addr_size = sizeof(clientAddr);
    clientSocket = accept(serverSocket, (struct sockaddr *)&clientAddr, &addr_size);
    if (clientSocket < 0)
    {
        log.write_log(log_location, "Работа модуля: communicator. Ошибка при аутентификации: ошибка принятия соединения клиента");
        std::cout << "Ошибка принятия соединения клиента" << std::endl;
        close(clientSocket);
    }
    else
    {
        log.write_log(log_location, "Работа модуля: communicator. Соединение с клиентом установлено");
        std::cout << "Соединение установлено" << std::endl;
    }
    cl_id = recv_data("Работа модуля: communicator. Ошибка при приеме айди клиента");
    std::cout << "Подсоединился пользователь: " + cl_id << std::endl;
}
communicator::communicator(uint port, std::string base_loc, std::string log_loc)
{
    p = port;
    base_location = base_loc;
    log_location = log_loc;
}
void communicator::start()
{
    serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket < 0)
    {
        perror("Ошибка при создании сокета");
        log.write_log(log_location, "Работа модуля: communicator. Ошибка при создании сокета сервера");
        throw critical_error("Сокет не был создан");
    }
    log.write_log(log_location, "Работа модуля: communicator. Сокет для сервера создан");
    std::cout << "Сокет создан" << std::endl;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(p);
    serverAddr.sin_addr.s_addr = INADDR_ANY;

    if (bind(serverSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0)
    {
        perror("Ошибка при привязке сокета");
        log.write_log(log_location, "Работа модуля: communicator. Ошибка при привязке сокета");
        throw critical_error("Сокет не был привязан");
    }
    log.write_log(log_location, "Работа модуля: communicator. Cокет привязан");
    std::cout << "Сокет привязан" << std::endl;
    connect_to_cl();
    std::cout << 1 << std::endl;
    send_file_list();
    std::cout << 2 << std::endl;
    std::chrono::milliseconds duration(1);
    std::this_thread::sleep_for(duration);
    std::string path=recv_data("test");
    send_file(path);
}
std::string communicator::recv_data(std::string messg)
{
    int rc = 0;
    while (true)
    {
        buffer = std::unique_ptr<char[]>(new char[buflen]);
        rc = recv(clientSocket, buffer.get(), buflen, MSG_PEEK);
        if (rc == 0)
        {
            close_sock();
            log.write_log(log_location, "Клиент закрыл соединение");
        }
        else if (rc < 0)
        {
            close_sock();
            log.write_log(log_location, messg);
        }
        if (rc < buflen)
            break;
        buflen *= 2;
    }
    std::string msg(buffer.get(), rc);
    recv(clientSocket, nullptr, rc, MSG_TRUNC);
    std::cout << "Строка принята" << std::endl;
    return msg;
}

void communicator::send_data(std::string data, std::string msg)
{
    std::unique_ptr<char[]> temp{new char[data.length() + 1]};
    strcpy(temp.get(), data.c_str());
    buffer = std::move(temp);
    int sb = send(clientSocket, buffer.get(), data.length(), 0);
    if (sb < 0)
    {
        log.write_log(log_location, msg);
        close_sock();
    }
}
void communicator::close_sock()
{
    close(clientSocket);
    log.write_log(log_location, "Работа модуля communicator. Разорвано соединение с клиентом");
}
void communicator::send_file_list()
{
    data_handler handler;
    std::vector<std::string> files = handler.get_file_list();
    if (files.empty()) {
        std::cerr << "Отправка вектора: список файлов пуст!" << std::endl;
        return;
    }
    
    uint32_t vector_size = htonl(files.size()); // Преобразуем порядок байтов
    if (send(clientSocket, &vector_size, sizeof(vector_size), 0) <= 0) {
        std::cerr << "Ошибка отправки размера вектора" << std::endl;
        return;
    }
    
    for (const auto& file : files) {
        uint32_t length = htonl(file.size());
        
        // Отправляем размер строки
        if (send(clientSocket, &length, sizeof(length), 0) <= 0) {
            std::cerr << "Ошибка отправки размера строки" << std::endl;
            return;
        }
        
        // Отправляем саму строку
        if (send(clientSocket, file.c_str(), file.size(), 0) <= 0) {
            std::cerr << "Ошибка отправки данных строки" << std::endl;
            return;
        }
    }
}
void communicator::send_file(std::string &file_path)
{
    std::ifstream file(file_path, std::ios::binary);
    if (!file)
    {
        std::cerr << "Ошибка открытия файла!" << std::endl;
        return;
    }

    uint64_t buffer; // 64 бита (8 байт)
    int i = 1;
    while (file.read(reinterpret_cast<char *>(&buffer), sizeof(buffer)) || file.gcount() > 0)
    {
        std::cout << "Отправлен " << i << "блок данных" << std::endl;
        send(clientSocket, &buffer, file.gcount(), 0);
    }

    // Отправляем маркер конца файла (нулевой блок)
    buffer = 0;
    send(clientSocket, &buffer, sizeof(buffer), 0);

    file.close();
    std::cout << "Файл успешно отправлен!" << std::endl;
}