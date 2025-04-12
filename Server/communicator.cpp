/** @file
 * @author Стригин А.В.
 * @version 1.0
 * @date 23.12.2023
 * @copyright ИБСТ ПГУ
 * @brief Исполняемый файл для модуля communicator*/
#include "communicator.h"

int communicator::connect_to_cl(int &new_socket)
{
    const std::string method_name = "connect_to_cl";

    std::cout << "[INFO] [" << method_name << "] Сервер запускает прослушивание порта..." << std::endl;
    if (listen(serverSocket, 10) != 0)
    {
        log.write_log(log_location, method_name + " | Ошибка при прослушивании порта");
        throw critical_error("Сервер не встал на прослушку");
    }

    log.write_log(log_location, method_name + " | Сервер слушает порт, ожидает подключение клиента");
    std::cout << "[INFO] [" << method_name << "] Ожидание подключения клиента..." << std::endl;

    addr_size = sizeof(clientAddr);
    new_socket = accept(serverSocket, (struct sockaddr *)&clientAddr, &addr_size);
    if (new_socket < 0)
    {
        log.write_log(log_location, method_name + " | Ошибка принятия соединения");
        std::cerr << "[ERROR] [" << method_name << "] Ошибка при принятии соединения!" << std::endl;
        return -1;
    }

    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(clientAddr.sin_addr), client_ip, INET_ADDRSTRLEN);
    int client_port = ntohs(clientAddr.sin_port);

    log.write_log(log_location, method_name + " | Установлено соединение с клиентом | IP: " + std::string(client_ip) +
                                    " | Порт: " + std::to_string(client_port));
    std::cout << "[INFO] [" << method_name << "] Подключен клиент: " << client_ip << ":" << client_port << std::endl;

    return 0;
}

int communicator::authentification(int client_socket, std::string cl_id)
{
    const std::string method_name = "authentification";

    // Получаем IP клиента
    sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    getpeername(client_socket, (struct sockaddr *)&addr, &addr_len);
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(addr.sin_addr), client_ip, INET_ADDRSTRLEN);

    log.write_log(log_location, method_name + " | Начата аутентификация клиента | ID: " + cl_id + " | IP: " + client_ip);
    std::cout << "[INFO] [" << method_name << "] Аутентификация клиента [" << cl_id << "] с IP " << client_ip << std::endl;

    if (db.selectUserByName(cl_id) == 0)
    {
        log.write_log(log_location, method_name + " | Клиент не найден в базе | ID: " + cl_id + " | IP: " + client_ip);
        close_sock(client_socket);
        return 0;
    }

    std::string cl_passw_base = db.getCurrentHashedPassword();
    std::string cl_ip_base = db.getCurrentIP();

    std::string cl_passw_recv = recv_data(client_socket, "Ошибка при приеме пароля");
    std::string cl_ip_recv = recv_data(client_socket, "Ошибка при приеме айпи");

    if (cl_passw_base != cl_passw_recv)
    {
        log.write_log(log_location, method_name + " | Неверный пароль | ID: " + cl_id + " | IP: " + client_ip);
        std::cerr << "[WARN] [" << method_name << "] Неверный пароль клиента [" << cl_id << "]" << std::endl;
        close_sock(client_socket);
        return 0;
    }

    if (cl_ip_base != cl_ip_recv)
    {
        log.write_log(log_location, method_name + " | Несовпадение IP-адреса | ID: " + cl_id + " | IP базы: " + cl_ip_base + " | IP получен: " + cl_ip_recv);
        std::cerr << "[WARN] [" << method_name << "] IP клиента не совпадает с базой [" << cl_id << "]" << std::endl;
        close_sock(client_socket);
        return 0;
    }

    log.write_log(log_location, method_name + " | Аутентификация успешна | ID: " + cl_id + " | IP: " + client_ip);
    std::cout << "[INFO] [" << method_name << "] Клиент [" << cl_id << "] успешно аутентифицирован" << std::endl;
    return 1;
}

void communicator::registration(int client_socket, std::string cl_id)
{
    const std::string method_name = "registration";

    // Получение IP клиента
    sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    getpeername(client_socket, (struct sockaddr *)&addr, &addr_len);
    char client_ip_cstr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(addr.sin_addr), client_ip_cstr, INET_ADDRSTRLEN);
    std::string client_ip_str = client_ip_cstr;

    log.write_log(log_location, method_name + " | Начата регистрация клиента | ID: " + cl_id + " | IP: " + client_ip_str);
    std::cout << "[INFO] [" << method_name << "] Регистрация клиента [" << cl_id << "] с IP " << client_ip_str << std::endl;

    std::string password = recv_data(client_socket, "Ошибка при приеме пароля");
    if (password.empty())
    {
        log.write_log(log_location, method_name + " | Не получен пароль клиента | ID: " + cl_id + " | IP: " + client_ip_str);
        std::cerr << "[ERROR] [" << method_name << "] Не удалось получить пароль от клиента [" << cl_id << "]" << std::endl;
        close_sock(client_socket);
        return;
    }

    db.insertUser(cl_id, password, client_ip_str);

    send_data(client_socket, "Аутентификация успешна", "Ошибка отправки отладочного сообщения");
    log.write_log(log_location, method_name + " | Регистрация завершена успешно | ID: " + cl_id + " | IP: " + client_ip_str);
    std::cout << "[INFO] [" << method_name << "] Регистрация клиента [" << cl_id << "] завершена успешно" << std::endl;

    close_sock(client_socket);
}

communicator::communicator(uint port,std::string log_loc)
{
    p = port;
    //base_location = base_loc;
    log_location = log_loc;
}
void communicator::work()
{
    const std::string method_name = "work";

    log.write_log(log_location, method_name + " | Запуск основного цикла сервера");
    std::cout << "[INFO] [" << method_name << "] Сервер запущен и ожидает подключения клиентов..." << std::endl;

    start();

    while (true)
    {
        int new_socket;
        int result = connect_to_cl(new_socket);

        if (result == 0)
        {
            log.write_log(log_location, method_name + " | Подключение клиента принято, создаётся поток для обработки");
            std::cout << "[INFO] [" << method_name << "] Принято новое подключение. Запуск потока обработки клиента." << std::endl;

            std::thread client_thread(&communicator::handle_client, this, new_socket);
            client_thread.detach();
        }
        else
        {
            log.write_log(log_location, method_name + " | Ошибка при подключении клиента");
            std::cerr << "[ERROR] [" << method_name << "] Ошибка подключения клиента, продолжаем ожидание..." << std::endl;
        }
    }
}

void communicator::handle_client(int client_socket)
{
    const std::string method_name = "handle_client";

    try
    {
        // Получаем ID клиента
        std::string cl_id = recv_data(client_socket, method_name + " | Ошибка при приеме ID клиента");
        std::string operation_type = recv_data(client_socket, method_name + " | Ошибка при приеме типа операции");

        char ip_buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(clientAddr.sin_addr), ip_buf, INET_ADDRSTRLEN);
        std::string client_ip = ip_buf;

        log.write_log(log_location, method_name + " | Установлено соединение с клиентом | ID: " + cl_id + " | IP: " + client_ip);
        std::cout << "[INFO] [" << method_name << "] Подключение от клиента: ID = " << cl_id << ", IP = " << client_ip << std::endl;

        // Делаем небольшую паузу для синхронизации
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        std::cout << "[INFO] [" << method_name << "] Получен тип операции: " << operation_type << std::endl;

        if (operation_type == "0")
        {
            log.write_log(log_location, method_name + " | Регистрация нового клиента | ID: " + cl_id + " | IP: " + client_ip);
            registration(client_socket, cl_id);
        }
        else
        {
            if (authentification(client_socket, cl_id) == 0)
            {
                log.write_log(log_location, method_name + " | Аутентификация не пройдена | ID: " + cl_id + " | IP: " + client_ip);
                return;
            }
            std::cout << "[INFO] [" << method_name << "] Успешная аутентификация клиента: " << cl_id << std::endl;
            log.write_log(log_location, method_name + " | Аутентификация пройдена | ID: " + cl_id + " | IP: " + client_ip);
        }

        // Обработка файлов
        log.write_log(log_location, method_name + " | Начата передача файлов | ID: " + cl_id + " | IP: " + client_ip);
        file_exchange(client_socket);
    }
    catch (const std::exception &e)
    {
        log.write_log(log_location, method_name + " | Критическая ошибка обработки клиента: " + std::string(e.what()));
        std::cerr << "[ERROR] [" << method_name << "] Исключение при обработке клиента: " << e.what() << std::endl;
        close_sock(client_socket);
    }
}

void communicator::start()
{
    const std::string method_name = "start";

    serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket < 0)
    {
        log.write_log(log_location, method_name + " | Ошибка при создании сокета");
        std::cerr << "[ERROR] [" << method_name << "] Ошибка при создании сокета" << std::endl;
        throw critical_error("Сокет не был создан");
    }

    log.write_log(log_location, method_name + " | Сокет для сервера создан");
    std::cout << "[INFO] [" << method_name << "] Сокет создан" << std::endl;

    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(p);
    serverAddr.sin_addr.s_addr = INADDR_ANY;

    if (bind(serverSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0)
    {
        log.write_log(log_location, method_name + " | Ошибка при привязке сокета");
        std::cerr << "[ERROR] [" << method_name << "] Ошибка при привязке сокета" << std::endl;
        throw critical_error("Сокет не был привязан");
    }

    log.write_log(log_location, method_name + " | Сокет привязан");
    std::cout << "[INFO] [" << method_name << "] Сокет привязан" << std::endl;
}

int communicator::file_exchange(int client_socket)
{
    const std::string method_name = "file_exchange";

    // Логируем начало работы метода
    log.write_log(log_location, method_name + " | Начало обмена файлами с клиентом (ID: " + std::to_string(client_socket) + ")");
    std::cout << "[INFO] [" << method_name << "] Начало обмена файлами с клиентом (ID: " << client_socket << ")" << std::endl;

    send_file_list(client_socket); // Отправляем список файлов

    while (true)
    {
        std::string path = recv_data(client_socket, "Ошибка при принятии пути к запрашиваемому файлу");

        if (path.empty())
        {
            log.write_log(log_location, method_name + " | Ошибка при приеме имени файла от клиента или клиент закрыл соединение (ID: " + std::to_string(client_socket) + ")");
            std::cerr << "[ERROR] [" << method_name << "] Ошибка при приеме имени файла от клиента/клиент закрыл соединение (ID: " << client_socket << ")" << std::endl;
            close_sock(client_socket);
            return 1;
        }

        // Логируем полученный путь к файлу
        log.write_log(log_location, method_name + " | Получен путь к файлу от клиента (ID: " + std::to_string(client_socket) + "): " + path);
        std::cout << "[INFO] [" << method_name << "] Получен путь к файлу от клиента (ID: " << client_socket << "): " << path << std::endl;

        if (send_file(client_socket, path) == 1)
        {
            log.write_log(log_location, method_name + " | Ошибка при отправке файла клиенту (ID: " + std::to_string(client_socket) + ")");
            std::cerr << "[ERROR] [" << method_name << "] Ошибка при отправке файла клиенту (ID: " << client_socket << ")" << std::endl;
            close_sock(client_socket);
            return 1;
        }
    }

    return 0;
}

std::string communicator::recv_data(int client_socket, std::string messg)
{
    const std::string method_name = "recv_data";
    timeout.tv_sec = 100;
    timeout.tv_usec = 0;
    setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));

    int rc = 0;
    size_t peek_buflen = buflen;
    std::vector<char> temp_buffer(peek_buflen);

    // Логируем начало приема данных
    log.write_log(log_location, method_name + " | Начало приема данных от клиента (ID: " + std::to_string(client_socket) + ")");
    std::cout << "[INFO] [" << method_name << "] Начало приема данных от клиента (ID: " << client_socket << ")" << std::endl;

    while (true)
    {
        rc = recv(client_socket, temp_buffer.data(), peek_buflen, MSG_PEEK);
        if (rc == 0)
        {
            close_sock(client_socket);
            log.write_log(log_location, method_name + " | Клиент закрыл соединение (ID: " + std::to_string(client_socket) + ")");
            std::cerr << "[ERROR] [" << method_name << "] Клиент закрыл соединение (ID: " << client_socket << ")" << std::endl;
            return "";
        }
        else if (rc < 0)
        {
            close_sock(client_socket);
            log.write_log(log_location, method_name + " | " + messg);
            std::cerr << "[ERROR] [" << method_name << "] " << messg << std::endl;
            return "";
        }

        if (static_cast<size_t>(rc) < peek_buflen)
            break;
        peek_buflen *= 2;
        temp_buffer.resize(peek_buflen);
    }

    std::string msg(temp_buffer.data(), rc);
    if (recv(client_socket, nullptr, rc, MSG_TRUNC) <= 0)
    {
        close_sock(client_socket);
        log.write_log(log_location, method_name + " | " + messg);
        std::cerr << "[ERROR] [" << method_name << "] " << messg << std::endl;
        return "";
    }

    // Логируем принятые данные
    log.write_log(log_location, method_name + " | Принятые данные от клиента (ID: " + std::to_string(client_socket) + "): " + msg);
    std::cout << "[INFO] [" << method_name << "] Строка принята от клиента (ID: " << client_socket << "): " << msg << std::endl;

    return msg;
}

void communicator::send_data(int client_socket, std::string data, std::string msg)
{
    const std::string method_name = "send_data";

    // Логируем начало отправки данных
    log.write_log(log_location, method_name + " | Начало отправки данных клиенту (ID: " + std::to_string(client_socket) + ")");
    std::cout << "[INFO] [" << method_name << "] Начало отправки данных клиенту (ID: " << client_socket << ")" << std::endl;

    std::chrono::milliseconds duration(10);
    std::unique_ptr<char[]> temp{new char[data.length() + 1]};
    strcpy(temp.get(), data.c_str());
    buffer = std::move(temp);
    std::this_thread::sleep_for(duration);

    // Отправка данных
    int sb = send(client_socket, buffer.get(), data.length(), 0);
    if (sb <= 0)
    {
        log.write_log(log_location, method_name + " | Ошибка отправки данных клиенту (ID: " + std::to_string(client_socket) + ")");
        std::cerr << "[ERROR] [" << method_name << "] Ошибка отправки данных клиенту (ID: " << client_socket << ")" << std::endl;
        close_sock(client_socket);
        return;
    }

    // Логируем успешную отправку данных
    log.write_log(log_location, method_name + " | Данные успешно отправлены клиенту (ID: " + std::to_string(client_socket) + ")");
    std::cout << "[INFO] [" << method_name << "] Данные успешно отправлены клиенту (ID: " << client_socket << ")" << std::endl;
}

void communicator::close_sock(int client_socket)
{
    const std::string method_name = "close_sock";

    // Логируем разрыв соединения
    log.write_log(log_location, method_name + " | Разорвано соединение с клиентом (ID: " + std::to_string(client_socket) + ")");
    std::cout << "[INFO] [" << method_name << "] Разорвано соединение с клиентом (ID: " << client_socket << ")" << std::endl;

    // Закрытие сокета
    close(client_socket);

    // Дополнительно, если нужно записывать дату и время разрыва соединения
    std::time_t now = std::time(nullptr);
    char timestamp[100];
    std::strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", std::localtime(&now));
    log.write_log(log_location, method_name + " | Время разрыва соединения: " + timestamp);
}

void communicator::send_file_list(int client_socket)
{
    const std::string method_name = "send_file_list";
    std::chrono::milliseconds duration(10);
    data_handler handler;
    std::vector<std::string> files = handler.get_file_list();

    if (files.empty())
    {
        std::cerr << "Отправка вектора: список файлов пуст!" << std::endl;
        log.write_log(log_location, method_name + " | Список файлов пуст");
        return;
    }

    uint32_t vector_size = htonl(files.size());
    std::this_thread::sleep_for(duration);
    if (send(client_socket, &vector_size, sizeof(vector_size), 0) <= 0)
    {
        close_sock(client_socket);
        std::cerr << "Ошибка отправки размера вектора" << std::endl;
        log.write_log(log_location, method_name + " | Ошибка отправки размера вектора");
        return;
    }

    for (const auto &file : files)
    {
        uint32_t length = htonl(file.size());

        std::this_thread::sleep_for(duration);
        if (send(client_socket, &length, sizeof(length), 0) <= 0)
        {
            close_sock(client_socket);
            std::cerr << "Ошибка отправки размера строки" << std::endl;
            log.write_log(log_location, method_name + " | Ошибка отправки размера строки");
            return;
        }

        std::this_thread::sleep_for(duration);
        if (send(client_socket, file.c_str(), file.size(), 0) <= 0)
        {
            close_sock(client_socket);
            std::cerr << "Ошибка отправки данных строки" << std::endl;
            log.write_log(log_location, method_name + " | Ошибка отправки данных строки");
            return;
        }
    }

    std::cout << "[INFO] " << method_name << " | Файлы успешно отправлены" << std::endl;
    log.write_log(log_location, method_name + " | Файлы успешно отправлены");
}

int communicator::send_file(int client_socket, std::string &file_path)
{
    const std::string method_name = "send_file";

    if (!boost::filesystem::exists(file_path))
    {
        std::cerr << "Такого запрашиваемого файла не существует" << std::endl;
        log.write_log(log_location, method_name + " | Файл не найден: " + file_path);
        close_sock(client_socket);
        return 1;
    }

    std::ifstream file(file_path, std::ios::binary | std::ios::ate);
    if (!file)
    {
        std::cerr << "Ошибка открытия файла!" << std::endl;
        log.write_log(log_location, method_name + " | Ошибка открытия файла: " + file_path);
        close_sock(client_socket);
        return 1;
    }

    std::streamsize file_size = file.tellg();
    file.seekg(0, std::ios::beg);

    int64_t size_net = htobe64(static_cast<int64_t>(file_size));
    if (send(client_socket, &size_net, sizeof(size_net), 0) <= 0)
    {
        std::cerr << "Ошибка отправки размера файла!" << std::endl;
        log.write_log(log_location, method_name + " | Ошибка отправки размера файла: " + file_path);
        close_sock(client_socket);
        return 1;
    }

    constexpr size_t BUFFER_SIZE = 65536;
    std::vector<char> buffer(BUFFER_SIZE);

    int total_bytes_sent = 0;
    int i = 0;

    while (file)
    {
        file.read(buffer.data(), BUFFER_SIZE);
        std::streamsize bytes_read = file.gcount();
        if (bytes_read <= 0)
            break;

        int bytes_sent = 0;
        while (bytes_sent < bytes_read)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            int sent = send(client_socket, buffer.data() + bytes_sent, bytes_read - bytes_sent, 0);
            if (sent <= 0)
            {
                std::cerr << "Ошибка отправки данных!" << std::endl;
                log.write_log(log_location, method_name + " | Ошибка отправки данных: " + file_path);
                close_sock(client_socket);
                file.close();
                return 1;
            }
            bytes_sent += sent;
        }

        total_bytes_sent += bytes_sent;
        std::cout << "[INFO] " << method_name << " | Отправлен блок #" << ++i << ", размер: " << bytes_sent << " байт" << std::endl;
    }

    file.close();
    std::cout << "[INFO] " << method_name << " | Файл успешно отправлен! Общий размер: " << total_bytes_sent << " байт" << std::endl;
    log.write_log(log_location, method_name + " | Файл успешно отправлен: " + file_path);
    return 0;
}
std::string communicator::hash_gen(std::string &password)
{
    CryptoPP::SHA256 hash;
    std::string hashed_password;

    CryptoPP::StringSource(password, true,
                           new CryptoPP::HashFilter(hash,
                                                    new CryptoPP::HexEncoder(
                                                        new CryptoPP::StringSink(hashed_password))));

    return hashed_password;
}