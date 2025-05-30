#include "communicator.h"

int communicator::connect_to_cl(int &new_socket, sockaddr_in &out_clientAddr)
{
    const std::string method_name = "connect_to_cl";

    // Начало прослушивания порта
    if (listen(serverSocket, 10) != 0)
    {
        log.write_log(log_location, method_name + " | Ошибка при прослушивании порта");
        throw critical_error("Сервер не встал на прослушку");
    }
    std::cout << "[INFO] [" << method_name << "] Ожидание подключения клиента" << std::endl;
    log.write_log(log_location, method_name + " | Ожидание подключения клиента...");
    addr_size = sizeof(out_clientAddr);
    new_socket = accept(serverSocket, (struct sockaddr *)&out_clientAddr, &addr_size);
    if (new_socket < 0)
    {
        log.write_log(log_location, method_name + " | Ошибка принятия соединения");
        std::cerr << "[ERROR] [" << method_name << "] Ошибка при принятии соединения!" << std::endl;
        return -1;
    }

    // Логируем информацию о клиенте
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(out_clientAddr.sin_addr), client_ip, INET_ADDRSTRLEN);
    int client_port = ntohs(out_clientAddr.sin_port);
    log.write_log(log_location, method_name + " | Подключен клиент | IP: " + std::string(client_ip) + " | Порт: " + std::to_string(client_port));

    return 0;
}

int communicator::authentification(int client_socket, std::string cl_id)
{
    const std::string method_name = "authentification";

    // Проверка валидности сокета
    if (client_socket < 0)
    {
        log.write_log(log_location, method_name + " | Некорректный сокет клиента");
        std::cerr << "[ERROR] [" << method_name << "] Некорректный сокет клиента" << std::endl;
        return 0;
    }

    // Генерация уникального ID сообщения
    int msg_id = MessageProtocol::generateMessageID();

    // Получаем IP клиента
    sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    if (getpeername(client_socket, reinterpret_cast<struct sockaddr *>(&addr), &addr_len) < 0)
    {
        log.write_log(log_location, method_name + " | Не удалось получить IP клиента");
    }
    char client_ip[INET_ADDRSTRLEN] = "";
    inet_ntop(AF_INET, &addr.sin_addr, client_ip, INET_ADDRSTRLEN);

    log.write_log(log_location, method_name + " | Начата аутентификация клиента | ID: " + cl_id + " | IP: " + client_ip);
    std::cout << "[INFO] [" << method_name << "] Аутентификация клиента [" << cl_id << "] с IP " << client_ip << std::endl;

    // Проверка существования пользователя
    if (db.selectUserByName(cl_id) == 0)
    {
        log.write_log(log_location, method_name + " | Клиент не найден в базе | ID: " + cl_id);
        send_data(client_socket, "UERR", cl_id, msg_id, "UERR");
        close_sock(client_socket);
        return 0;
    }

    // Получение ожидаемых данных из БД
    std::string cl_passw_base = db.getCurrentHashedPassword();
    std::string cl_ip_base = db.getCurrentIP();

    // Приём пароля и IP от клиента
    std::string cl_passw_recv = recv_data(client_socket, "Ошибка при приеме пароля");
    std::string cl_ip_recv = recv_data(client_socket, "Ошибка при приеме IP");

    // Проверка пароля
    if (cl_passw_base != cl_passw_recv)
    {
        log.write_log(log_location, method_name + " | Неверный пароль | ID: " + cl_id);
        std::cerr << "[WARN] [" << method_name << "] Неверный пароль клиента [" << cl_id << "]" << std::endl;
        send_data(client_socket, "PERR", cl_id, msg_id, "PERR");
        close_sock(client_socket);
        return 0;
    }

    // Проверка IP-адреса
    if (cl_ip_base != cl_ip_recv)
    {
        log.write_log(log_location, method_name + " | Несовпадение IP-адреса | ID: " + cl_id +
                                        " | Ожидалось: " + cl_ip_base + " | Получено: " + cl_ip_recv);
        std::cerr << "[WARN] [" << method_name << "] IP клиента не совпадает с базой [" << cl_id << "]" << std::endl;
        send_data(client_socket, "IERR", cl_id, msg_id, "IERR");
        close_sock(client_socket);
        return 0;
    }

    // Успешная аутентификация
    send_data(client_socket, "OK", cl_id, msg_id, "Аутентификация успешна");
    log.write_log(log_location, method_name + " | Аутентификация успешна | ID: " + cl_id + " | IP: " + client_ip);
    std::cout << "[INFO] [" << method_name << "] Клиент [" << cl_id << "] успешно аутентифицирован" << std::endl;

    return 1;
}

int communicator::registration(int client_socket, std::string cl_id)
{
    const std::string method_name = "registration";

    // Проверка валидности сокета
    if (client_socket < 0)
    {
        log.write_log(log_location, method_name + " | Некорректный сокет клиента");
        std::cerr << "[ERROR] [" << method_name << "] Некорректный сокет клиента" << std::endl;
        return 1;
    }

    // Генерация уникального ID сообщения
    int msg_id = MessageProtocol::generateMessageID();

    // Получаем IP клиента
    sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    if (getpeername(client_socket, reinterpret_cast<struct sockaddr *>(&addr), &addr_len) < 0)
    {
        log.write_log(log_location, method_name + " | Не удалось получить IP клиента");
    }
    char client_ip_cstr[INET_ADDRSTRLEN] = "";
    inet_ntop(AF_INET, &addr.sin_addr, client_ip_cstr, INET_ADDRSTRLEN);
    std::string client_ip_str = client_ip_cstr;

    log.write_log(log_location, method_name + " | Начата регистрация клиента | ID: " + cl_id + " | IP: " + client_ip_str);
    std::cout << "[INFO] [" << method_name << "] Регистрация клиента [" << cl_id << "] с IP " << client_ip_str << std::endl;

    // Получаем пароль от клиента
    std::string password = recv_data(client_socket, "Ошибка при приеме пароля");
    if (password.empty())
    {
        log.write_log(log_location, method_name + " | Не получен пароль клиента | ID: " + cl_id + " | IP: " + client_ip_str);
        std::cerr << "[ERROR] [" << method_name << "] Не удалось получить пароль от клиента [" << cl_id << "]" << std::endl;
        close_sock(client_socket);
        return 1;
    }

    // Вставляем нового пользователя в базу данных
    if (db.insertUser(cl_id, password, client_ip_str) == false)
    {
        send_data(client_socket, "REG_OK", cl_id, msg_id, "Ошибка регистрации");
        close_sock(client_socket);
        std::cout << "[INFO] [" << method_name << "] Регистрация клиента [" << cl_id << "] не завершена, ошибка при запросе к БД" << std::endl;
        return 1;
    }

    // Отправляем клиенту протокольное сообщение об успешной регистрации
    send_data(client_socket, "REG_OK", cl_id, msg_id, "Регистрация успешна");

    log.write_log(log_location, method_name + " | Регистрация завершена успешно | ID: " + cl_id + " | IP: " + client_ip_str);
    std::cout << "[INFO] [" << method_name << "] Регистрация клиента [" << cl_id << "] завершена успешно" << std::endl;

    // Закрываем соединение
    close_sock(client_socket);
}

communicator::communicator(uint port, std::string log_loc)
{
    p = port;
    // base_location = base_loc;
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
        sockaddr_in client_addr;
        int result = connect_to_cl(new_socket, client_addr);

        if (result != 0)
        {
            log.write_log(log_location, method_name + " | Ошибка при подключении клиента");
            std::cerr << "[ERROR] [" << method_name << "] Ошибка подключения клиента, продолжаем ожидание..." << std::endl;
            continue;
        }
        int prev = active_clients.fetch_add(1);
        // Проверяем, есть ли свободный слот
        if (prev >= 3)
        {
            active_clients.fetch_sub(1);
            send_data(new_socket, "CONN_ERR", "server", -1, "Сервер полон");
            close_sock(new_socket);

            log.write_log(log_location, method_name + " | Отклонено подключение: очередь заполнена");
            std::cout << "[INFO] [" << method_name << "] Отклонено новое подключение: очередь заполнена." << std::endl;
            continue;
        }
        send_data(new_socket, "CONN_OK", "server", -1, "Подключение успешно");
        // Логируем успешное подключение клиента и создание потока
        log.write_log(log_location, method_name + " | Подключение клиента принято, создаётся поток для обработки");
        std::cout << "[INFO] [" << method_name << "] Принято новое подключение. Запуск потока обработки клиента." << std::endl;

        // Создаем поток
        std::thread client_thread(&communicator::handle_client, this, new_socket, client_addr);
        client_thread.detach();
    }
}
void communicator::handle_client(int client_socket, sockaddr_in clientAddr)
{
    const std::string method_name = "handle_client";
    //active_clients.fetch_add(1);
    try
    {
        // Получаем ID клиента
        std::string cl_id = recv_data(client_socket, method_name + " | Ошибка при приеме ID клиента");
        std::string operation_type = recv_data(client_socket, method_name + " | Ошибка при приеме типа операции");

        // Получаем IP клиента
        char ip_buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(clientAddr.sin_addr), ip_buf, INET_ADDRSTRLEN);
        std::string client_ip = ip_buf;

        // Логируем подключение клиента
        log.write_log(log_location, method_name + " | Установлено соединение с клиентом | ID: " + cl_id + " | IP: " + client_ip);
        std::cout << "[INFO] [" << method_name << "] Подключение от клиента: ID = " << cl_id << ", IP = " << client_ip << std::endl;

        // Небольшая задержка для синхронизации
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        std::cout << "[INFO] [" << method_name << "] Получен тип операции: " << operation_type << std::endl;

        // Регистрация нового клиента
        if (operation_type == "0")
        {
            log.write_log(log_location, method_name + " | Регистрация нового клиента | ID: " + cl_id + " | IP: " + client_ip);
            if (registration(client_socket, cl_id) == 1)
            {
                active_clients.fetch_sub(1);
                return;
            }
            close_sock(client_socket);
            active_clients.fetch_sub(1);
            return;
        }
        else
        {
            // Аутентификация клиента
            if (authentification(client_socket, cl_id) == 0)
            {
                log.write_log(log_location, method_name + " | Аутентификация не пройдена | ID: " + cl_id + " | IP: " + client_ip);
                active_clients.fetch_sub(1);
                return;
            }
            std::cout << "[INFO] [" << method_name << "] Успешная аутентификация клиента: " << cl_id << std::endl;
            log.write_log(log_location, method_name + " | Аутентификация пройдена | ID: " + cl_id + " | IP: " + client_ip);
        }

        // Передача файлов
        log.write_log(log_location, method_name + " | Начата передача файлов | ID: " + cl_id + " | IP: " + client_ip);
        if (file_exchange(client_socket) == 1)
        {
            active_clients.fetch_sub(1);
            close_sock(client_socket);
            return;
        }
        active_clients.fetch_sub(1);
    }
    catch (const std::exception &e)
    {
        // Логируем и выводим ошибку при исключении
        log.write_log(log_location, method_name + " | Критическая ошибка обработки клиента: " + std::string(e.what()));
        std::cerr << "[ERROR] [" << method_name << "] Исключение при обработке клиента: " << e.what() << std::endl;
        active_clients.fetch_sub(1);
        close_sock(client_socket);
    }
}

void communicator::start()
{
    const std::string method_name = "start";

    // Создание сокета для сервера
    serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket < 0)
    {
        log.write_log(log_location, method_name + " | Ошибка при создании сокета");
        std::cerr << "[ERROR] [" << method_name << "] Ошибка при создании сокета" << std::endl;
        throw critical_error("Сокет не был создан");
    }

    // Логируем успешное создание сокета
    log.write_log(log_location, method_name + " | Сокет для сервера создан");
    std::cout << "[INFO] [" << method_name << "] Сокет создан" << std::endl;

    // Настройка структуры адреса для привязки
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(p);          // Устанавливаем порт
    serverAddr.sin_addr.s_addr = INADDR_ANY; // Принимаем соединения с любого IP

    // Привязка сокета к адресу
    if (bind(serverSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0)
    {
        log.write_log(log_location, method_name + " | Ошибка при привязке сокета");
        std::cerr << "[ERROR] [" << method_name << "] Ошибка при привязке сокета" << std::endl;
        throw critical_error("Сокет не был привязан");
    }

    // Логируем успешную привязку сокета
    log.write_log(log_location, method_name + " | Сокет привязан");
    std::cout << "[INFO] [" << method_name << "] Сокет привязан" << std::endl;
}
int communicator::file_exchange(int client_socket)
{
    const std::string method_name = "file_exchange";

    // Логируем начало обмена файлами с клиентом
    log.write_log(log_location, method_name + " | Начало обмена файлами с клиентом (ID: " + std::to_string(client_socket) + ")");
    std::cout << "[INFO] [" << method_name << "] Начало обмена файлами с клиентом (ID: " << client_socket << ")" << std::endl;

    // Отправка списка файлов клиенту
    if (send_file_list(client_socket) == 1)
    {
        return 1;
    }

    while (true)
    {
        std::cout << "[INFO] [" << method_name << "] Ожидание пути файла от  (ID: " << client_socket << ")" << std::endl;
        // Получение пути к запрашиваемому файлу от клиента
        std::string path = recv_data(client_socket, "Ошибка при принятии пути к запрашиваемому файлу");

        // Проверка, если путь пустой (клиент закрыл соединение или ошибка)
        if (path.empty())
        {
            log.write_log(log_location, method_name + " | Ошибка при приеме имени файла от клиента или клиент закрыл соединение (ID: " + std::to_string(client_socket) + ")");
            std::cerr << "[ERROR] [" << method_name << "] Ошибка при приеме имени файла от клиента/клиент закрыл соединение (ID: " << client_socket << ")" << std::endl;
            // close_sock(client_socket);
            return 1;
        }

        // Логируем полученный путь к файлу
        log.write_log(log_location, method_name + " | Получен путь к файлу от клиента (ID: " + std::to_string(client_socket) + "): " + path);
        std::cout << "[INFO] [" << method_name << "] Получен путь к файлу от клиента (ID: " << client_socket << "): " << path << std::endl;
        int file_send = send_file(client_socket, path);
        // Отправка запрашиваемого файла клиенту
        if (file_send == 1)
        {
            log.write_log(log_location, method_name + " | Ошибка при отправке файла клиенту (ID: " + std::to_string(client_socket) + ")");
            std::cerr << "[ERROR] [" << method_name << "] Ошибка при отправке файла клиенту (ID: " << client_socket << ")" << std::endl;
            // close_sock(client_socket);
            return 1;
        }
        if (file_send == 2)
        {
            log.write_log(log_location, method_name + " | Ошибка при отправке файла клиенту. Не удалось открыть файл или файл не найден (ID: " + std::to_string(client_socket) + ")");
            std::cerr << "[ERROR] [" << method_name << "] Ошибка при отправке файла клиенту. Не удалось открыть файл или файл не найден (ID: " << client_socket << ")" << std::endl;
            // close_sock(client_socket);
            continue;
        }
    }

    return 0;
}
std::string communicator::recv_data(int client_socket, std::string error_msg)
{
    const std::string method_name = "recv_data";

    // Устанавливаем таймаут на приём данных
    timeout.tv_sec = 100;
    timeout.tv_usec = 0;
    setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));

    std::vector<char> buffer(buflen);
    int received_bytes = recv(client_socket, buffer.data(), buflen, MSG_NOSIGNAL);

    if (received_bytes <= 0)
    {
        close_sock(client_socket);
        log.write_log(log_location, method_name + " | Ошибка или закрыто соединение: " + error_msg);
        std::cerr << "[ERROR] [" << method_name << "] " << error_msg << std::endl;
        return "";
    }

    try
    {
        std::string raw_data(buffer.data(), received_bytes);
        log.write_log(log_location, method_name + " | Принято протокольное сообщение от клиента (ID: " + std::to_string(client_socket) + "): " + raw_data);
        MessageProtocol::ParsedMessage message = MessageProtocol::parse(raw_data);
        std::cout << "[INFO] [" << method_name << "] Принято сообщение: " << message.message << std::endl;
        return message.message; // Возвращаем только полезную нагрузку
    }
    catch (const std::exception &e)
    {
        log.write_log(log_location, method_name + " | Ошибка парсинга протокольного сообщения: " + std::string(e.what()));
        std::cerr << "[ERROR] [" << method_name << "] Ошибка парсинга: " << e.what() << std::endl;
        return "";
    }
}
int communicator::send_data(int client_socket, const std::string &header,
                            const std::string &client_id, int message_id,
                            const std::string &msg)
{
    const std::string method_name = "send_data";

    if (client_socket < 0)
    {
        log.write_log(log_location, method_name + " | Некорректный сокет клиента");
        std::cerr << "[ERROR] [" << method_name << "] Некорректный сокет клиента" << std::endl;
        return 1;
    }

    log.write_log(log_location, method_name + " | Подготовка отправки данных клиенту (ID: " + std::to_string(client_socket) + ")");
    std::cout << "[INFO] [" << method_name << "] Подготовка отправки данных клиенту (ID: " << client_socket << ")" << std::endl;

    // 1) формируем основной пакет с полезной нагрузкой
    std::string packet = MessageProtocol::build(header, client_id, message_id, msg);

    // 2) формируем пакет LENGTH по протоколу, содержащий длину payload
    std::string len_payload = std::to_string(packet.size());
    std::string len_packet = MessageProtocol::build("LENGTH", client_id, message_id, len_payload);
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    // отправляем пакет LENGTH целиком
    size_t sent = 0;
    const char *len_data = len_packet.data();
    size_t len_size = len_packet.size();
    while (sent < len_size)
    {
        int n = send(client_socket, len_data + sent, len_size - sent, MSG_NOSIGNAL);
        if (n <= 0)
        {
            log.write_log(log_location, method_name + " | Ошибка отправки LENGTH" + std::to_string(sent) + " байт");
            std::cerr << "[ERROR] [" << method_name << "] Ошибка отправки LENGTH, n=" << n << std::endl;
            // close_sock(client_socket);
            return 1;
        }
        sent += n;
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(30));

    // 3) отправляем основной пакет целиком
    sent = 0;
    const char *data = packet.data();
    size_t packet_size = packet.size();
    while (sent < packet_size)
    {
        int n = send(client_socket, data + sent, packet_size - sent, MSG_NOSIGNAL);
        if (n <= 0)
        {
            log.write_log(log_location, method_name + " | Ошибка отправки DATA после " + std::to_string(sent) + " байт");
            std::cerr << "[ERROR] [" << method_name << "] Ошибка отправки DATA, n=" << n << std::endl;
            // close_sock(client_socket);
            return 1;
        }
        sent += n;
    }

    log.write_log(log_location, method_name + " | Успешно отправлено пакетов LENGTH и " + header + " клиенту (ID: " + std::to_string(client_socket) + ")");
    std::cout << "[INFO] [" << method_name << "] Успешно отправлено пакетов LENGTH и " << header << " клиенту (ID: " << client_socket << ")" << std::endl;
}

void communicator::close_sock(int client_socket)
{
    const std::string method_name = "close_sock";

    // Логируем разрыв соединения
    log.write_log(log_location, method_name + " | Разорвано соединение с клиентом (ID: " + std::to_string(client_socket) + ")");
    std::cout << "[INFO] [" << method_name << "] Разорвано соединение с клиентом (ID: " << client_socket << ")" << std::endl;
    //int before = active_clients.fetch_sub(1);
    /*if (before <= 0)
    {
        log.write_log(log_location, "close_sock | Предупреждение: число активных клиентов стало меньше нуля");
        active_clients.store(0); // аварийное восстановление
    }*/
    // Закрытие сокета
    close(client_socket);

    // Дополнительно, если нужно записывать дату и время разрыва соединения
    std::time_t now = std::time(nullptr);
    char timestamp[100];
    std::strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", std::localtime(&now));
    log.write_log(log_location, method_name + " | Время разрыва соединения: " + timestamp);
}

int communicator::send_file_list(int client_socket)
{
    const std::string method_name = "send_file_list";
    std::chrono::milliseconds duration(10);
    data_handler handler;
    std::vector<std::string> files = handler.get_file_list();

    if (files.empty())
    {
        log.write_log(log_location, method_name + " | Список файлов пуст");
        std::cerr << "[WARN] [" << method_name << "] Список файлов пуст" << std::endl;
        return 1;
    }

    int msg_id = MessageProtocol::generateMessageID();

    // Отправляем количество файлов
    if (send_data(client_socket, "FILE_COUNT", "server", msg_id, std::to_string(files.size())) == 1)
    {
        return 1;
    }
    std::this_thread::sleep_for(duration);

    // Отправка каждого файла
    for (const auto &file : files)
    {
        msg_id = MessageProtocol::generateMessageID();
        if (send_data(client_socket, "FILE_ENTRY", "server", msg_id, file) == 1)
        {
            return 1;
        }
        std::this_thread::sleep_for(duration);
    }

    log.write_log(log_location, method_name + " | Все файлы успешно отправлены клиенту");
    std::cout << "[INFO] [" << method_name << "] Все файлы успешно отправлены клиенту" << std::endl;
}

int communicator::send_file(int client_socket, std::string &file_path)
{
    const std::string method_name = "send_file";
    int msg_id = MessageProtocol::generateMessageID();
    if (client_socket < 0)
    {
        log.write_log(log_location, method_name + " | Некорректный сокет клиента");
        std::cerr << "[ERROR] [" << method_name << "] Некорректный сокет клиента" << std::endl;
        return 1;
    }

    if (!boost::filesystem::exists(file_path))
    {
        log.write_log(log_location, method_name + " | Файл не найден: " + file_path);
        std::cerr << "[ERROR] [" << method_name << "] Файл не найден: " << file_path << std::endl;
        if (send_data(client_socket, "FILE_ERR", "server", msg_id, "Файл не найден") == 1)
        {
            return 2;
        }
        // close_sock(client_socket);
        return 2;
    }

    std::ifstream file(file_path, std::ios::binary | std::ios::ate);
    if (!file)
    {
        log.write_log(log_location, method_name + " | Ошибка открытия файла: " + file_path);
        std::cerr << "[ERROR] [" << method_name << "] Ошибка открытия файла: " << file_path << std::endl;
        if (send_data(client_socket, "FILE_ERR", "server", msg_id, "Ошибка открытия файла") == 1)
        {
            return 2;
        }
        // close_sock(client_socket);
        return 2;
    }

    std::streamsize file_size = file.tellg();
    file.seekg(0, std::ios::beg);

    if (send_data(client_socket, "FILE_SIZE", "server", msg_id, std::to_string(file_size)) == 1)
    {
        return 1;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));

    constexpr size_t BUFFER_SIZE = 65536;
    std::vector<char> buffer(BUFFER_SIZE);
    int total_bytes_sent = 0;
    int block_index = 0;

    while (file)
    {
        file.read(buffer.data(), BUFFER_SIZE);
        std::streamsize bytes_read = file.gcount();
        if (bytes_read <= 0)
            break;

        std::string data_chunk(buffer.data(), bytes_read);
        msg_id = MessageProtocol::generateMessageID();
        if (send_data(client_socket, "FILE_CHUNK", "server", msg_id, data_chunk) == 1)
        {
            return 1;
        }
        // std::this_thread::sleep_for(std::chrono::milliseconds(50));

        total_bytes_sent += bytes_read;
        std::cout << "[INFO] [" << method_name << "] Отправлен блок #" << block_index++
                  << ", размер: " << bytes_read << " байт" << std::endl;
    }

    file.close();

    msg_id = MessageProtocol::generateMessageID();
    if (send_data(client_socket, "FILE_END", "server", msg_id, "EOF") == 1)
    {
        return 1;
    }

    std::cout << "[INFO] [" << method_name << "] Файл успешно отправлен! Общий размер: "
              << total_bytes_sent << " байт" << std::endl;
    log.write_log(log_location, method_name + " | Файл успешно отправлен: " + file_path);
    return 0;
}

std::string communicator::hash_gen(std::string &password)
{
    // Создаем объект для алгоритма хэширования SHA256
    CryptoPP::SHA256 hash;
    std::string hashed_password;

    // Применяем хэширование:
    // StringSource - источник данных (строка с паролем), передаем его в хэш-фильтр
    // HashFilter - фильтрует и хэширует данные через алгоритм SHA256
    // HexEncoder - кодирует результат хэширования в строку в формате шестнадцатеричных символов
    // StringSink - принимает результат в виде строки
    CryptoPP::StringSource(password, true,
                           new CryptoPP::HashFilter(hash,
                                                    new CryptoPP::HexEncoder(
                                                        new CryptoPP::StringSink(hashed_password))));

    // Возвращаем хэшированную строку пароля
    return hashed_password;
}
