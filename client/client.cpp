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
    const std::string method_name = "client::work";
    serv_ip = intf.get_serv_ip().c_str();
    port = intf.get_port();
    op = intf.get_op();
    password = intf.get_password();
    id = intf.get_username();

    std::cout << "[INFO] " << method_name << " | Начало работы клиента." << std::endl;

    start();
    connect_to_server();
    
    std::chrono::milliseconds duration(10);
    send_data(std::to_string(op));

    if (op == 1) {
        std::cout << "[INFO] " << method_name << " | Выполняется аутентификация клиента..." << std::endl;
        client_auth();
        std::cout << "[INFO] " << method_name << " | Аутентификация успешна." << std::endl;
    } else {
        std::cout << "[INFO] " << method_name << " | Выполняется регистрация клиента..." << std::endl;
        client_reg();
        std::cout << "[INFO] " << method_name << " | Регистрация успешна." << std::endl;
    }

    files = recv_vector();
    std::cout << "[INFO] " << method_name << " | Получен список файлов с сервера:" << std::endl;
    print_vector(files);

    while (true)
    {
        std::chrono::milliseconds dur(100);
        std::this_thread::sleep_for(duration);

        std::string file_path;
        std::string path;

        std::cout << "[INFO] " << method_name << " | Введите путь к файлу данных: ";
        std::getline(std::cin, file_path);

        std::cout << "[INFO] " << method_name << " | Введите путь к тестовому файлу: ";
        std::getline(std::cin, path);

        std::cout << "[INFO] " << method_name << " | Отправка пути файла на сервер: " << file_path << std::endl;
        send_data(file_path);

        std::cout << "[INFO] " << method_name << " | Получение файла..." << std::endl;
        if (recv_file(path) == 1) {
            std::cout << "[ERROR] " << method_name << " | Ошибка при получении файла: " << path << std::endl;
            continue;
        }

        std::cout << "[INFO] " << method_name << " | Файл успешно получен: " << path << std::endl;
    }

    close_sock();
    std::cout << "[INFO] " << method_name << " | Клиент завершил работу." << std::endl;
    exit(1);
}

void client::client_reg() {
    const std::string method_name = "client::client_reg";

    std::cout << "[INFO] " << method_name << " | Инициализация регистрации пользователя..." << std::endl;
    
    std::cout << "[INFO] " << method_name << " | Генерация хэша пароля для отправки на сервер..." << std::endl;
    std::string hashed_password = hash_gen(password);
    
    std::cout << "[INFO] " << method_name << " | Отправка хэшированного пароля на сервер..." << std::endl;
    send_data(hashed_password);

    std::cout << "[INFO] " << method_name << " | Ожидание ответа от сервера..." << std::endl;
    recv_data();

    std::cout << "[INFO] " << method_name << " | Регистрация завершена. Закрытие соединения." << std::endl;
    close_sock();
    
    std::cout << "[INFO] " << method_name << " | Завершение работы клиента." << std::endl;
    exit(1);
}
void client::client_auth() {
    std::chrono::milliseconds duration(30);

    std::cout << "[INFO] Начало аутентификации..." << std::endl;
    std::this_thread::sleep_for(duration);

    std::cout << "[INFO] Отправка хэшированного пароля..." << std::endl;
    send_data(hash_gen(password));
    std::this_thread::sleep_for(duration);

    std::cout << "[INFO] Отправка IP-адреса клиента..." << std::endl;
    send_data(ip);

    std::cout << "[INFO] Аутентификация завершена" << std::endl;
}

void client::start()
{
    std::cout << "[INFO] Начало создания сокета..." << std::endl;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
    {
        debugger.show_error_information("Ошибка в start()", "Возможная причина - неверные параметры socket()", "Синтаксическая ошибка");
        std::cerr << "[ERROR] Не удалось создать сокет!" << std::endl;
        return;
    }
    
    std::cout << "[INFO] Сокет успешно создан" << std::endl;

    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    
    std::cout << "[INFO] Настройка адреса сервера: " << serv_ip << ":" << port << std::endl;
    inet_pton(AF_INET, serv_ip, &serverAddr.sin_addr);

    std::cout << "[INFO] Адрес сервера успешно настроен" << std::endl;
}

void client::connect_to_server()
{
    std::cout << "[INFO] Получаем информацию о локальном сокете..." << std::endl;
    sockaddr_in localAddr{};
    socklen_t addrLen = sizeof(localAddr);

    // Получаем локальный адрес сокета
    if (getsockname(sock, (struct sockaddr*)&localAddr, &addrLen) < 0) {
        std::cerr << "[ERROR] Ошибка получения информации о сокете" << std::endl;
        return;
    }
    std::cout << "[INFO] Локальный адрес сокета получен: " << inet_ntoa(localAddr.sin_addr) << std::endl;

    // Проверка, если IP сервера равен 127.0.0.1
    if (serverAddr.sin_addr.s_addr == htonl(INADDR_LOOPBACK)) {
        ip = "127.0.0.1";  // Если сервер локальный
        std::cout << "[INFO] Сервер локальный. Используется IP: 127.0.0.1" << std::endl;
    } else {
        // Если сервер не локальный, получаем свой сетевой IP
        ip = inet_ntoa(localAddr.sin_addr);
        std::cout << "[INFO] Сервер не локальный. Используется IP: " << ip << std::endl;
    }

    // Пытаемся подключиться к серверу
    std::cout << "[INFO] Пытаемся подключиться к серверу..." << std::endl;
    if (connect(sock, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0) {
        close_sock();
        std::cerr << "[ERROR] Ошибка подключения к серверу. Проверьте IP или порт." << std::endl;
        debugger.show_error_information("Ошибка в connect_to_server()", "Возможная причина - неверный айпи или порт сервера", "Логическая ошибка");
        return;
    }

    std::cout << "[INFO] Клиент успешно подключился к серверу" << std::endl;

    // Отправляем идентификатор
    std::cout << "[INFO] Отправляем идентификатор клиента: " << id << std::endl;
    send_data(id);
}

std::string client::recv_data()
{
    const std::string method_name = "recv_data";
    timeout.tv_sec = 10;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    
    std::chrono::milliseconds duration(10);
    int rc = 0;

    std::cout << "[INFO] " << method_name << " | Ожидаем данные от сервера..." << std::endl;

    while (true)
    {
        buffer = std::unique_ptr<char[]>(new char[buflen]);
        std::this_thread::sleep_for(duration);
        
        rc = recv(sock, buffer.get(), buflen, MSG_PEEK);
        
        if (rc == 0)
        {
            std::cerr << "[ERROR] " << method_name << " | Принято 0 байт от сервера. Закрываем сокет." << std::endl;
            close_sock();
            debugger.show_error_information("Ошибка в recv_data()", "Принято 0 байт от сервера", "Логическая ошибка");
            return "";  // Возвращаем пустую строку в случае ошибки
        }
        else if (rc < 0)
        {
            std::cerr << "[ERROR] " << method_name << " | Ошибка при получении данных: recv() вернуло " << rc << std::endl;
            close_sock();
            debugger.show_error_information("Ошибка в recv_data()", "Результат recv = -1", "Логическая ошибка");
            return "";  // Возвращаем пустую строку в случае ошибки
        }

        if (rc < buflen)
            break;
        
        // Увеличиваем буфер, если данные не поместились в текущий
        buflen *= 2;
        std::cout << "[INFO] " << method_name << " | Увеличиваем буфер до " << buflen << " байт." << std::endl;
    }

    std::string msg(buffer.get(), rc);

    std::this_thread::sleep_for(duration);
    
    if (recv(sock, nullptr, rc, MSG_TRUNC) < 0)
    {
        std::cerr << "[ERROR] " << method_name << " | Ошибка при подтверждении получения данных (MSG_TRUNC)." << std::endl;
        close_sock();
        debugger.show_error_information("Ошибка в recv_data()", "Результат recv = -1", "Логическая ошибка");
        return "";  // Возвращаем пустую строку в случае ошибки
    }

    std::cout << "[INFO] " << method_name << " | Данные успешно получены от сервера. Размер данных: " << rc << " байт." << std::endl;

    return msg;
}

void client::close_sock()
{
    std::cout << "[INFO] Закрытие сокета клиента..." << std::endl;
    if (close(sock) == 0)
    {
        std::cout << "[INFO] Сокет клиента успешно закрыт" << std::endl;
    }
    else
    {
        std::cerr << "[ERROR] Ошибка при закрытии сокета клиента" << std::endl;
    }
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
        std::cerr << "[ERROR] Ошибка отправки данных строкового типа" << std::endl;
        close_sock();
        debugger.show_error_information("Ошибка в send_data() - string", "Результат send = -1", "Логическая ошибка");
        return;
    }

    std::cout << "[INFO] Отправлены данные строкового типа: \"" << data << "\" (Размер: " << data.length() << " байт)" << std::endl;
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
        std::cerr << "[ERROR] Ошибка при получении размера вектора" << std::endl;
        close_sock();
        debugger.show_error_information("Ошибка в recv_vector()", "Возможная причина - ошибка на стороне сервера при отправке размера вектора", "Логическая ошибка");
        return received_vector;
    }
    vec_size = ntohl(vec_size); // Преобразуем порядок байтов
    std::cout << "[INFO] Получен размер вектора: " << vec_size << " элементов" << std::endl;

    // Получаем строки
    for (uint32_t i = 0; i < vec_size; ++i) {
        uint32_t str_size = 0;
        std::this_thread::sleep_for(duration);

        // Получаем размер строки
        if (recv(sock, &str_size, sizeof(str_size), 0) <= 0) {
            std::cerr << "[ERROR] Ошибка при получении размера строки #" << i + 1 << std::endl;
            debugger.show_error_information("Ошибка в recv_vector()", "Возможная причина - ошибка на стороне сервера при отправке размера строки", "Логическая ошибка");
            close_sock();
            return received_vector;
        }
        str_size = ntohl(str_size);
        std::cout << "[INFO] Получен размер строки #" << i + 1 << ": " << str_size << " байт" << std::endl;

        std::this_thread::sleep_for(duration);
        
        // Получаем саму строку
        std::unique_ptr<char[]> buffer(new char[str_size + 1]);
        if (recv(sock, buffer.get(), str_size, 0) <= 0) {
            std::cerr << "[ERROR] Ошибка при получении строки #" << i + 1 << std::endl;
            debugger.show_error_information("Ошибка в recv_vector()", "Возможная причина - ошибка на стороне сервера при отправке строки", "Логическая ошибка");
            close_sock();
            return received_vector;
        }
        buffer[str_size] = '\0';  // Завершаем строку символом конца строки

        received_vector.emplace_back(buffer.get());
        std::cout << "[INFO] Строка #" << i + 1 << " успешно получена: " << buffer.get() << std::endl;
    }

    std::cout << "[INFO] Вектор успешно получен, количество строк: " << received_vector.size() << std::endl;
    return received_vector;
}
void client::print_vector(const std::vector<std::string> &vec)
{
    if (vec.empty()) {
        std::cout << "[INFO] Список файлов пуст." << std::endl;
        return;
    }

    std::cout << "[INFO] Список файлов:" << std::endl;
    std::cout << "-----------------------------" << std::endl;
    
    for (size_t i = 0; i < vec.size(); ++i)
    {
        std::cout << std::setw(3) << i + 1 << ". " << std::left << std::setw(40) << vec[i] << std::endl;
    }

    std::cout << "-----------------------------" << std::endl;
    std::cout << "[INFO] Общее количество файлов: " << vec.size() << std::endl;
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
        std::cerr << "[ERROR] Ошибка открытия файла для записи!" << std::endl;
        return 1;
    }

    // Приём размера файла (8 байт)
    int64_t file_size_net = 0;
    int received = recv(sock, &file_size_net, sizeof(file_size_net), MSG_WAITALL);
    if (received != sizeof(file_size_net))
    {
        std::cerr << "[ERROR] Не удалось получить размер файла!" << std::endl;
        file.close();
        return 1;
    }

    int64_t file_size = be64toh(file_size_net);
    std::cout << "[INFO] Размер файла к получению: " << file_size << " байт" << std::endl;

    constexpr size_t BUFFER_SIZE = 65536;
    std::vector<char> buffer(BUFFER_SIZE);

    int64_t total_bytes_received = 0;
    int block_count = 0;

    while (total_bytes_received < file_size)
    {
        size_t to_receive = std::min(static_cast<int64_t>(BUFFER_SIZE), file_size - total_bytes_received);
        int bytes_received = recv(sock, buffer.data(), to_receive, 0);

        if (bytes_received < 0)
        {
            std::cerr << "[ERROR] Ошибка при получении данных!" << std::endl;
            file.close();
            return 1;
        }

        if (bytes_received == 0)
        {
            std::cerr << "[ERROR] Сервер преждевременно закрыл соединение!" << std::endl;
            file.close();
            return 1;
        }

        file.write(buffer.data(), bytes_received);
        total_bytes_received += bytes_received;
        std::cout << "[INFO] Принят блок #" << ++block_count << ", размер: " << bytes_received << " байт" << std::endl;
        std::cout << "[INFO] Принято данных: " << total_bytes_received << "/" << file_size << " байт" << std::endl;
    }

    file.close();
    std::cout << "[INFO] Файл успешно принят! Общий размер: " << total_bytes_received << " байт" << std::endl;
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