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
    serv_ip = intf.get_serv_ip().c_str();
    port = intf.get_port();
    op = intf.get_op();
    password = intf.get_password();
    id=intf.get_username();
    std::cout << "Начало работы клиента" << std::endl;
    start();
    connect_to_server();
    std::chrono::milliseconds duration(10);
    send_data(std::to_string(op));
    if (op==1){
        client_auth();
    }
    else{
        client_reg();
    }
    files = recv_vector();
    print_vector(files);
    while (true)
    {
        std::chrono::milliseconds dur(100);
        std::this_thread::sleep_for(duration);
        std::string file_path;
        std::string path;

        std::cout << "Введите путь к файлу данных: ";
        std::getline(std::cin, file_path);

        std::cout << "Введите путь к тестовому файлу: ";
        std::getline(std::cin, path);
        send_data(file_path);
        if(recv_file(path)==1){
            continue;
        }
        //std::this_thread::sleep_for(dur);
    }
    close_sock();
    exit(1);
}
void client::client_reg(){
    send_data(hash_gen(password));
    recv_data();
    close_sock();
    exit(1);
}
void client::client_auth(){
    std::chrono::milliseconds duration(30);
    std::this_thread::sleep_for(duration);
    send_data(hash_gen(password));
    std::this_thread::sleep_for(duration);
    send_data(ip);
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
    sockaddr_in localAddr{};
    socklen_t addrLen = sizeof(localAddr);

    // Получаем локальный адрес сокета
    if (getsockname(sock, (struct sockaddr*)&localAddr, &addrLen) < 0) {
        std::cerr << "Ошибка получения информации о сокете" << std::endl;
        return;
    }

    // Проверка, если IP сервера равен 127.0.0.1
    if (serverAddr.sin_addr.s_addr == htonl(INADDR_LOOPBACK)) {
        ip = "127.0.0.1";  // Если сервер локальный
    } else {
        // Если сервер не локальный, получаем свой сетевой IP
        ip = inet_ntoa(localAddr.sin_addr);
    }

    // Пытаемся подключиться к серверу
    if (connect(sock, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0) {
        close_sock();
        debugger.show_error_information("Ошибка в connect_to_server()", "Возможная причина - неверный айпи или порт сервера", "Логическая ошибка");
        return;
    }

    std::cout << "Клиент соединился с сервером" << std::endl;

    // Отправляем идентификатор
    send_data(id);
}
std::string client::recv_data()
{
    timeout.tv_sec = 10;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    std::chrono::milliseconds duration(10);
    int rc = 0;
    while (true)
    {
        buffer = std::unique_ptr<char[]>(new char[buflen]);
        std::this_thread::sleep_for(duration);
        rc = recv(sock, buffer.get(), buflen, MSG_PEEK);
        if (rc == 0)
        {
            close_sock();
            debugger.show_error_information("Ошибка в recv_data()", "Принято 0 байт от сервера", "Логическая ошибка");
        }
        else if (rc < 0)
        {
            close_sock();
            debugger.show_error_information("Ошибка в recv_data()", "Результат recv = -1", "Логическая ошибка");
        }
        if (rc < buflen)
            break;
        buflen *= 2;
    }
    std::string msg(buffer.get(), rc);
    std::this_thread::sleep_for(duration);
    if(recv(sock, nullptr, rc, MSG_TRUNC)<0){
        close_sock();
        debugger.show_error_information("Ошибка в recv_data()", "Результат recv = -1", "Логическая ошибка");
    }
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
    std::chrono::milliseconds duration(10);
    std::unique_ptr<char[]> temp{new char[data.length() + 1]};
    strcpy(temp.get(), data.c_str());
    buffer = std::move(temp);
    std::this_thread::sleep_for(duration);
    int sb = send(sock, buffer.get(), data.length(), 0);
    if (sb < 0)
    {
        close_sock();
        debugger.show_error_information("Ошибка в send_data() - string", "Результат send = -1", "Логическая ошибка");
    }
    std::cout << "Отправлены данные строкового типа: "<<data << std::endl;
}
std::vector<std::string> client::recv_vector() {
    timeout.tv_sec = 10;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    std::vector<std::string> received_vector;
    std::chrono::milliseconds duration(10);
    // Получаем размер вектора
    uint32_t vec_size = 0;
    std::this_thread::sleep_for(duration);
    if (recv(sock, &vec_size, sizeof(vec_size), 0) <= 0) {
        std::cerr << "Ошибка при получении размера вектора" << std::endl;
        close_sock();
        debugger.show_error_information("Ошибка в recv_vector()", "Возможная причина - ошибка на стороне сервера при отправке размера вектора", "Логическая ошибка");
        return received_vector;
    }
    vec_size = ntohl(vec_size); // Преобразуем порядок байтов

    // Получаем строки
    for (uint32_t i = 0; i < vec_size; ++i) {
        uint32_t str_size = 0;
        std::this_thread::sleep_for(duration);
        // Получаем размер строки
        if (recv(sock, &str_size, sizeof(str_size), 0) <= 0) {
            std::cerr << "Ошибка при получении размера строки" << std::endl;
            debugger.show_error_information("Ошибка в recv_vector()", "Возможная причина - ошибка на стороне сервера при отправке размера строки", "Логическая ошибка");
            close_sock();
            return received_vector;
        }
        str_size = ntohl(str_size);
        std::this_thread::sleep_for(duration);
        // Получаем саму строку
        std::unique_ptr<char[]> buffer(new char[str_size + 1]);
        if (recv(sock, buffer.get(), str_size, 0) <= 0) {
            std::cerr << "Ошибка при получении строки" << std::endl;
            debugger.show_error_information("Ошибка в recv_vector()", "Возможная причина - ошибка на стороне сервера при отправке строки", "Логическая ошибка");
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
int client::recv_file(std::string &file_path)
{
    // Установка таймаута
    timeout.tv_sec = 10;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));

    std::ofstream file(file_path, std::ios::binary);
    if (!file)
    {
        std::cerr << "Ошибка открытия файла для записи!" << std::endl;
        return 1;
    }

    // Приём размера файла (8 байт)
    int64_t file_size_net = 0;
    int received = recv(sock, &file_size_net, sizeof(file_size_net), MSG_WAITALL);
    if (received != sizeof(file_size_net))
    {
        std::cerr << "Не удалось получить размер файла!" << std::endl;
        file.close();
        return 1;
    }

    int64_t file_size = be64toh(file_size_net);
    std::cout << "Размер файла к получению: " << file_size << " байт" << std::endl;

    constexpr size_t BUFFER_SIZE = 65536;
    std::vector<char> buffer(BUFFER_SIZE);

    int64_t total_bytes_received = 0;
    int i = 0;

    while (total_bytes_received < file_size)
    {
        size_t to_receive = std::min(static_cast<int64_t>(BUFFER_SIZE), file_size - total_bytes_received);
        int bytes_received = recv(sock, buffer.data(), to_receive, 0);

        if (bytes_received < 0)
        {
            std::cerr << "Ошибка при получении данных!" << std::endl;
            file.close();
            return 1;
        }

        if (bytes_received == 0)
        {
            std::cerr << "Сервер преждевременно закрыл соединение!" << std::endl;
            file.close();
            return 1;
        }

        file.write(buffer.data(), bytes_received);
        total_bytes_received += bytes_received;
        std::cout << "Принят блок #" << ++i << ", размер: " << bytes_received << " байт" << std::endl;
    }

    file.close();
    std::cout << "Файл успешно принят! Общий размер: " << total_bytes_received << " байт" << std::endl;
    return 0;
}


std::string client::hash_gen(std::string password){
    CryptoPP::SHA256 hash;
    std::string hashed_password;

    CryptoPP::StringSource(password, true,
        new CryptoPP::HashFilter(hash,
            new CryptoPP::HexEncoder(
                new CryptoPP::StringSink(hashed_password)
            )
        )
    );

    return hashed_password;
}