#include "communicator.h"

int communicator::connect_to_cl(int &new_socket)
{
    const std::string method_name = "connect_to_cl";

    // Начало прослушивания порта
    if (listen(serverSocket, 10) != 0)
    {
        log.write_log(log_location, method_name + " | Ошибка при прослушивании порта");
        throw critical_error("Сервер не встал на прослушку");
    }

    log.write_log(log_location, method_name + " | Ожидание подключения клиента...");
    addr_size = sizeof(clientAddr);

    // Принятие подключения клиента
    new_socket = accept(serverSocket, (struct sockaddr *)&clientAddr, &addr_size);
    if (new_socket < 0)
    {
        log.write_log(log_location, method_name + " | Ошибка принятия соединения");
        std::cerr << "[ERROR] [" << method_name << "] Ошибка при принятии соединения!" << std::endl;
        return -1;
    }

    // Логируем информацию о клиенте
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(clientAddr.sin_addr), client_ip, INET_ADDRSTRLEN);
    int client_port = ntohs(clientAddr.sin_port);
    log.write_log(log_location, method_name + " | Подключен клиент | IP: " + std::string(client_ip) + " | Порт: " + std::to_string(client_port));

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

    // Логируем начало процесса аутентификации
    log.write_log(log_location, method_name + " | Начата аутентификация клиента | ID: " + cl_id + " | IP: " + client_ip);
    std::cout << "[INFO] [" << method_name << "] Аутентификация клиента [" << cl_id << "] с IP " << client_ip << std::endl;

    // Проверяем существование клиента в базе данных
    if (db.selectUserByName(cl_id) == 0)
    {
        log.write_log(log_location, method_name + " | Клиент не найден в базе | ID: " + cl_id + " | IP: " + client_ip);
        send_data(client_socket, "UERR", method_name + " | Ошибка при отправке сообщения об отказе в аутентификации");
        close_sock(client_socket);
        return 0;
    }

    // Получаем данные из базы
    std::string cl_passw_base = db.getCurrentHashedPassword();
    std::string cl_ip_base = db.getCurrentIP();

    // Получаем данные от клиента
    std::string cl_passw_recv = recv_data(client_socket, "Ошибка при приеме пароля");
    std::string cl_ip_recv = recv_data(client_socket, "Ошибка при приеме айпи");

    // Сравниваем пароли
    if (cl_passw_base != cl_passw_recv)
    {
        log.write_log(log_location, method_name + " | Неверный пароль | ID: " + cl_id + " | IP: " + client_ip);
        std::cerr << "[WARN] [" << method_name << "] Неверный пароль клиента [" << cl_id << "]" << std::endl;
        send_data(client_socket, "PERR", method_name + " | Ошибка при отправке сообщения об отказе в аутентификации");
        close_sock(client_socket);
        return 0;
    }

    // Сравниваем IP адреса
    if (cl_ip_base != cl_ip_recv)
    {
        log.write_log(log_location, method_name + " | Несовпадение IP-адреса | ID: " + cl_id + " | IP базы: " + cl_ip_base + " | IP получен: " + cl_ip_recv);
        std::cerr << "[WARN] [" << method_name << "] IP клиента не совпадает с базой [" << cl_id << "]" << std::endl;
        send_data(client_socket, "IERR", method_name + " | Ошибка при отправке сообщения об отказе в аутентификации");
        close_sock(client_socket);
        return 0;
    }

    // Если все проверки прошли, отправляем успешный ответ
    send_data(client_socket, "OK", method_name + " | Ошибка при отправке сообщения об аутентификации");
    log.write_log(log_location, method_name + " | Аутентификация успешна | ID: " + cl_id + " | IP: " + client_ip);
    std::cout << "[INFO] [" << method_name << "] Клиент [" << cl_id << "] успешно аутентифицирован" << std::endl;
    return 1;
}

void communicator::registration(int client_socket, std::string cl_id)
{
    const std::string method_name = "registration";

    // Получаем IP клиента
    sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    getpeername(client_socket, (struct sockaddr *)&addr, &addr_len);
    char client_ip_cstr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(addr.sin_addr), client_ip_cstr, INET_ADDRSTRLEN);
    std::string client_ip_str = client_ip_cstr;

    // Логируем начало процесса регистрации
    log.write_log(log_location, method_name + " | Начата регистрация клиента | ID: " + cl_id + " | IP: " + client_ip_str);
    std::cout << "[INFO] [" << method_name << "] Регистрация клиента [" << cl_id << "] с IP " << client_ip_str << std::endl;

    // Получаем пароль от клиента
    std::string password = recv_data(client_socket, "Ошибка при приеме пароля");
    if (password.empty())
    {
        log.write_log(log_location, method_name + " | Не получен пароль клиента | ID: " + cl_id + " | IP: " + client_ip_str);
        std::cerr << "[ERROR] [" << method_name << "] Не удалось получить пароль от клиента [" << cl_id << "]" << std::endl;
        close_sock(client_socket);
        return;
    }

    // Вставляем нового пользователя в базу данных
    db.insertUser(cl_id, password, client_ip_str);

    // Отправляем клиенту сообщение об успешной регистрации
    send_data(client_socket, "Регистрация успешна", "Ошибка отправки отладочного сообщения");

    // Логируем успешную регистрацию
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

    // Логируем начало работы сервера
    log.write_log(log_location, method_name + " | Запуск основного цикла сервера");
    std::cout << "[INFO] [" << method_name << "] Сервер запущен и ожидает подключения клиентов..." << std::endl;

    // Инициализируем сервер
    start();

    while (true)
    {
        int new_socket;
        // Ожидаем подключения клиента
        int result = connect_to_cl(new_socket);

        if (result == 0)
        {
            // Логируем успешное подключение клиента и создание потока
            log.write_log(log_location, method_name + " | Подключение клиента принято, создаётся поток для обработки");
            std::cout << "[INFO] [" << method_name << "] Принято новое подключение. Запуск потока обработки клиента." << std::endl;

            // Создаем новый поток для обработки клиента и сразу его отсоединяем (поток работает независимо)
            std::thread client_thread(&communicator::handle_client, this, new_socket);
            client_thread.detach();
        }
        else
        {
            // Логируем ошибку при подключении клиента
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
            registration(client_socket, cl_id);
            close_sock(client_socket);
            return;
        }
        else
        {
            // Аутентификация клиента
            if (authentification(client_socket, cl_id) == 0)
            {
                log.write_log(log_location, method_name + " | Аутентификация не пройдена | ID: " + cl_id + " | IP: " + client_ip);
                return;
            }
            std::cout << "[INFO] [" << method_name << "] Успешная аутентификация клиента: " << cl_id << std::endl;
            log.write_log(log_location, method_name + " | Аутентификация пройдена | ID: " + cl_id + " | IP: " + client_ip);
        }

        // Передача файлов
        log.write_log(log_location, method_name + " | Начата передача файлов | ID: " + cl_id + " | IP: " + client_ip);
        file_exchange(client_socket);
    }
    catch (const std::exception &e)
    {
        // Логируем и выводим ошибку при исключении
        log.write_log(log_location, method_name + " | Критическая ошибка обработки клиента: " + std::string(e.what()));
        std::cerr << "[ERROR] [" << method_name << "] Исключение при обработке клиента: " << e.what() << std::endl;
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
    send_file_list(client_socket);

    while (true)
    {
        // Получение пути к запрашиваемому файлу от клиента
        std::string path = recv_data(client_socket, "Ошибка при принятии пути к запрашиваемому файлу");

        // Проверка, если путь пустой (клиент закрыл соединение или ошибка)
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

        // Отправка запрашиваемого файла клиенту
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

    // Устанавливаем таймаут на приём данных (100 секунд)
    timeout.tv_sec = 100;
    timeout.tv_usec = 0;
    setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));

    int rc = 0;
    size_t peek_buflen = buflen;
    std::vector<char> temp_buffer(peek_buflen);

    // Логируем начало приёма данных
    log.write_log(log_location, method_name + " | Начало приема данных от клиента (ID: " + std::to_string(client_socket) + ")");
    std::cout << "[INFO] [" << method_name << "] Начало приема данных от клиента (ID: " << client_socket << ")" << std::endl;

    // Чтение данных с флагом MSG_PEEK, чтобы узнать размер доступного сообщения
    while (true)
    {
        rc = recv(client_socket, temp_buffer.data(), peek_buflen, MSG_PEEK); // не удаляет данные из буфера
        if (rc == 0)
        {
            // Клиент закрыл соединение
            close_sock(client_socket);
            log.write_log(log_location, method_name + " | Клиент закрыл соединение (ID: " + std::to_string(client_socket) + ")");
            std::cerr << "[ERROR] [" << method_name << "] Клиент закрыл соединение (ID: " << client_socket << ")" << std::endl;
            return "";
        }
        else if (rc < 0)
        {
            // Ошибка при получении данных
            close_sock(client_socket);
            log.write_log(log_location, method_name + " | " + messg);
            std::cerr << "[ERROR] [" << method_name << "] " << messg << std::endl;
            return "";
        }

        // Если считано меньше, чем размер буфера — значит всё сообщение доступно
        if (static_cast<size_t>(rc) < peek_buflen)
            break;

        // Иначе удваиваем буфер и пробуем снова
        peek_buflen *= 2;
        temp_buffer.resize(peek_buflen);
    }

    // Преобразуем принятые байты в строку
    std::string msg(temp_buffer.data(), rc);

    // Удаляем прочитанные данные из буфера с помощью MSG_TRUNC
    if (recv(client_socket, nullptr, rc, MSG_TRUNC) <= 0)
    {
        // Ошибка при очистке буфера
        close_sock(client_socket);
        log.write_log(log_location, method_name + " | " + messg);
        std::cerr << "[ERROR] [" << method_name << "] " << messg << std::endl;
        return "";
    }

    // Логируем успешно принятые данные
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

    // Пауза для синхронизации (предотвращение наложения пакетов)
    std::chrono::milliseconds duration(10);

    // Создаем временный буфер и копируем туда строку
    std::unique_ptr<char[]> temp{new char[data.length() + 1]};
    strcpy(temp.get(), data.c_str());

    // Присваиваем буфер для отправки
    buffer = std::move(temp);

    // Ждем перед отправкой
    std::this_thread::sleep_for(duration);

    // Отправка строки клиенту
    int sb = send(client_socket, buffer.get(), data.length(), 0);
    if (sb <= 0)
    {
        // Ошибка отправки
        log.write_log(log_location, method_name + " | Ошибка отправки данных клиенту (ID: " + std::to_string(client_socket) + ")");
        std::cerr << "[ERROR] [" << method_name << "] Ошибка отправки данных клиенту (ID: " << client_socket << ")" << std::endl;
        close_sock(client_socket);
        return;
    }

    // Лог успешной отправки
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
    std::chrono::milliseconds duration(10); // Пауза между отправками для синхронизации

    data_handler handler;
    std::vector<std::string> files = handler.get_file_list(); // Получение списка файлов

    // Проверка: если список пуст, логируем и выходим
    if (files.empty())
    {
        std::cerr << "Отправка вектора: список файлов пуст!" << std::endl;
        log.write_log(log_location, method_name + " | Список файлов пуст");
        return;
    }

    // Отправляем размер вектора (кол-во файлов), приведённый к сетевому порядку байт
    uint32_t vector_size = htonl(files.size());
    std::this_thread::sleep_for(duration); // Пауза перед отправкой
    if (send(client_socket, &vector_size, sizeof(vector_size), 0) <= 0)
    {
        // Ошибка отправки — логируем и закрываем соединение
        close_sock(client_socket);
        std::cerr << "Ошибка отправки размера вектора" << std::endl;
        log.write_log(log_location, method_name + " | Ошибка отправки размера вектора");
        return;
    }

    // Поочередно отправляем каждый файл из списка
    for (const auto &file : files)
    {
        // Сначала отправляем длину строки (имени файла)
        uint32_t length = htonl(file.size());

        std::this_thread::sleep_for(duration); // Пауза
        if (send(client_socket, &length, sizeof(length), 0) <= 0)
        {
            close_sock(client_socket);
            std::cerr << "Ошибка отправки размера строки" << std::endl;
            log.write_log(log_location, method_name + " | Ошибка отправки размера строки");
            return;
        }

        // Затем отправляем само имя файла
        std::this_thread::sleep_for(duration); // Пауза
        if (send(client_socket, file.c_str(), file.size(), 0) <= 0)
        {
            close_sock(client_socket);
            std::cerr << "Ошибка отправки данных строки" << std::endl;
            log.write_log(log_location, method_name + " | Ошибка отправки данных строки");
            return;
        }
    }

    // Все файлы успешно отправлены — логируем
    std::cout << "[INFO] " << method_name << " | Файлы успешно отправлены" << std::endl;
    log.write_log(log_location, method_name + " | Файлы успешно отправлены");
}

int communicator::send_file(int client_socket, std::string &file_path)
{
    const std::string method_name = "send_file";

    // Проверка существования файла по указанному пути
    if (!boost::filesystem::exists(file_path))
    {
        std::cerr << "Такого запрашиваемого файла не существует" << std::endl;
        log.write_log(log_location, method_name + " | Файл не найден: " + file_path);
        close_sock(client_socket);
        return 1;
    }

    // Открываем файл в бинарном режиме для чтения
    std::ifstream file(file_path, std::ios::binary | std::ios::ate);
    if (!file)
    {
        std::cerr << "Ошибка открытия файла!" << std::endl;
        log.write_log(log_location, method_name + " | Ошибка открытия файла: " + file_path);
        close_sock(client_socket);
        return 1;
    }

    // Получаем размер файла
    std::streamsize file_size = file.tellg();
    file.seekg(0, std::ios::beg);

    // Отправляем размер файла в сетевом порядке байт
    int64_t size_net = htobe64(static_cast<int64_t>(file_size));
    if (send(client_socket, &size_net, sizeof(size_net), 0) <= 0)
    {
        std::cerr << "Ошибка отправки размера файла!" << std::endl;
        log.write_log(log_location, method_name + " | Ошибка отправки размера файла: " + file_path);
        close_sock(client_socket);
        return 1;
    }

    // Размер буфера для отправки данных
    constexpr size_t BUFFER_SIZE = 262144; // 128 KB
    std::vector<char> buffer(BUFFER_SIZE);

    int total_bytes_sent = 0; // Общее количество отправленных байт
    int i = 0;                // Индекс блока

    // Чтение файла и отправка блоками
    while (file)
    {
        file.read(buffer.data(), BUFFER_SIZE); // Чтение блока данных
        std::streamsize bytes_read = file.gcount();
        if (bytes_read <= 0)
            break; // Если не удалось прочитать данные, выходим

        int bytes_sent = 0;
        // Отправка данных по частям (если блок данных больше, чем размер буфера)
        while (bytes_sent < bytes_read)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(10)); // Пауза между отправками для синхронизации
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

        total_bytes_sent += bytes_sent; // Обновляем количество отправленных байт
        std::cout << "[INFO] " << method_name << " | Отправлен блок #" << ++i << ", размер: " << bytes_sent << " байт" << std::endl;
    }

    // Закрытие файла после отправки
    file.close();

    // Логируем успешную отправку файла
    std::cout << "[INFO] " << method_name << " | Файл успешно отправлен! Общий размер: " << total_bytes_sent << " байт" << std::endl;
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
