#include "client.h"
void client::work(UI &intf)
{
    const std::string method_name = "client::work";

    // Получаем параметры из интерфейса пользователя
    serv_ip = intf.get_serv_ip().c_str(); // IP адрес сервера
    port = intf.get_port();               // Порт для подключения
    op = intf.get_op();                   // Операция: регистрация или аутентификация
    password = intf.get_password();       // Пароль
    id = intf.get_username();             // Имя пользователя

    std::cout << "[INFO] " << method_name << " | Начало работы клиента." << std::endl;

    start();             // Инициализация клиента
    connect_to_server(); // Подключение к серверу

    std::chrono::milliseconds duration(10); // Задержка для стабилизации
    send_data(std::to_string(op));          // Отправляем информацию о типе операции (регистрация или аутентификация)

    // В зависимости от выбранной операции выполняем аутентификацию или регистрацию
    if (op == 1)
    {
        std::cout << "[INFO] " << method_name << " | Выполняется аутентификация клиента..." << std::endl;
        client_auth(); // Выполняем аутентификацию
        std::cout << "[INFO] " << method_name << " | Аутентификация успешна." << std::endl;
    }
    else
    {
        std::cout << "[INFO] " << method_name << " | Выполняется регистрация клиента..." << std::endl;
        client_reg(); // Выполняем регистрацию
        std::cout << "[INFO] " << method_name << " | Регистрация успешна." << std::endl;
    }

    // Получаем список файлов с сервера
    files = recv_vector();
    std::cout << "[INFO] " << method_name << " | Получен список файлов с сервера:" << std::endl;
    print_vector(files); // Выводим список файлов

    // Основной цикл работы клиента
    while (true)
    {
        std::chrono::milliseconds dur(100);    // Задержка между итерациями
        std::this_thread::sleep_for(duration); // Ожидаем немного

        std::string file_path; // Путь к запрашиваемому файлу
        std::string path;      // Путь для сохранения файла

        // Вводим путь к файлу
        std::cout << "[INFO] " << method_name << " | Введите путь к файлу данных: ";
        std::getline(std::cin, file_path);

        // Вводим путь для сохранения полученного файла
        std::cout << "[INFO] " << method_name << " | Введите путь для сохранения запрашиваемого файла: ";
        std::getline(std::cin, path);

        // Отправляем на сервер путь к запрашиваемому файлу
        std::cout << "[INFO] " << method_name << " | Отправка пути файла на сервер: " << file_path << std::endl;
        send_data(file_path);

        // Получаем файл с сервера
        std::cout << "[INFO] " << method_name << " | Получение файла..." << std::endl;
        if (recv_file(path) == 1)
        { // Если возникла ошибка при получении файла
            std::cout << "[ERROR] " << method_name << " | Ошибка при получении файла: " << path << std::endl;
            continue; // Пропускаем итерацию, продолжаем работу
        }

        // Если файл успешно получен
        std::cout << "[INFO] " << method_name << " | Файл успешно получен: " << path << std::endl;
    }

    close_sock(); // Закрываем соединение
    std::cout << "[INFO] " << method_name << " | Клиент завершил работу." << std::endl;
    exit(1); // Завершаем работу клиента
}

void client::client_reg()
{
    const std::string method_name = "client::client_reg";

    // Начало регистрации пользователя
    std::cout << "[INFO] " << method_name << " | Инициализация регистрации пользователя..." << std::endl;

    // Генерация хэша пароля для отправки на сервер
    std::cout << "[INFO] " << method_name << " | Генерация хэша пароля для отправки на сервер..." << std::endl;
    std::string hashed_password = hash_gen(password); // Хэшируем пароль

    // Отправка хэшированного пароля на сервер
    std::cout << "[INFO] " << method_name << " | Отправка хэшированного пароля на сервер..." << std::endl;
    send_data(hashed_password); // Отправляем хэш пароля серверу

    // Ожидание ответа от сервера
    std::cout << "[INFO] " << method_name << " | Ожидание ответа от сервера..." << std::endl;
    std::string answ = recv_data(); // Получаем ответ от сервера

    // Проверка ответа от сервера
    if (answ != "Регистрация успешна")
    {
        close_sock(); // Закрытие соединения
        // Показать информацию об ошибке, если регистрация не успешна
        debugger.show_error_information("Ошибка в client_reg()", "Возможная причина - ошибка запроса к БД на сервере", "Логическая ошибка");
    }

    // Если регистрация успешна
    std::cout << "[INFO] " << method_name << " | Регистрация завершена. Закрытие соединения." << std::endl;
    close_sock(); // Закрытие соединения

    // Завершаем работу клиента
    std::cout << "[INFO] " << method_name << " | Завершение работы клиента." << std::endl;
    exit(1); // Завершаем выполнение программы
}

void client::client_auth()
{
    std::chrono::milliseconds duration(30); // Задержка для стабилизации

    // Начало аутентификации
    std::cout << "[INFO] Начало аутентификации..." << std::endl;
    std::this_thread::sleep_for(duration); // Ожидаем немного

    // Отправка хэшированного пароля на сервер
    std::cout << "[INFO] Отправка хэшированного пароля..." << std::endl;
    send_data(hash_gen(password));         // Хэшируем пароль и отправляем на сервер
    std::this_thread::sleep_for(duration); // Ожидаем немного

    // Отправка IP-адреса клиента
    std::cout << "[INFO] Отправка IP-адреса клиента..." << std::endl;
    send_data(ip); // Отправляем IP-адрес клиента

    // Получаем ответ от сервера
    std::string flag = recv_data(); // Ответ от сервера (флаг ошибки или успешности)

    // Обработка флага ошибки
    if (flag != "OK")
    {
        std::cout << "[INFO] Флаг ошибки: " << flag << std::endl;
        // Показать информацию об ошибке в зависимости от флага
        debugger.show_error_information("Ошибка в client_auth()", "UERR - неверное имя пользователя \n PERR - неверный пароль \n IERR - неверный айпи", "Логическая ошибка");
    }

    // Если аутентификация успешна
    std::cout << "[INFO] Аутентификация завершена" << std::endl;
}

void client::start()
{
    std::cout << "[INFO] Начало создания сокета..." << std::endl;

    // Создаем сокет
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
    {
        debugger.show_error_information("Ошибка в start()", "Возможная причина - неверные параметры socket()", "Синтаксическая ошибка");
        std::cerr << "[ERROR] Не удалось создать сокет!" << std::endl;
        return;
    }

    std::cout << "[INFO] Сокет успешно создан" << std::endl;

    // Настроим параметры подключения
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
    if (getsockname(sock, (struct sockaddr *)&localAddr, &addrLen) < 0)
    {
        std::cerr << "[ERROR] Ошибка получения информации о сокете" << std::endl;
        return;
    }
    std::cout << "[INFO] Локальный адрес сокета получен: " << inet_ntoa(localAddr.sin_addr) << std::endl;

    // Проверка, если IP сервера равен 127.0.0.1 (локальный сервер)
    if (serverAddr.sin_addr.s_addr == htonl(INADDR_LOOPBACK))
    {
        ip = "127.0.0.1"; // Если сервер локальный
        std::cout << "[INFO] Сервер локальный. Используется IP: 127.0.0.1" << std::endl;
    }
    else
    {
        // Если сервер не локальный, получаем свой сетевой IP
        ip = inet_ntoa(localAddr.sin_addr);
        std::cout << "[INFO] Сервер не локальный. Используется IP: " << ip << std::endl;
    }

    // Пытаемся подключиться к серверу
    std::cout << "[INFO] Пытаемся подключиться к серверу..." << std::endl;
    if (connect(sock, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0)
    {
        close_sock();
        std::cerr << "[ERROR] Ошибка подключения к серверу. Проверьте IP или порт." << std::endl;
        debugger.show_error_information("Ошибка в connect_to_server()", "Возможная причина - неверный айпи или порт сервера", "Логическая ошибка");
        return;
    }

    std::cout << "[INFO] Клиент успешно подключился к серверу" << std::endl;

    // Отправляем идентификатор клиента
    std::cout << "[INFO] Отправляем идентификатор клиента: " << id << std::endl;
    send_data(id);
}
std::string client::recv_data()
{
    const std::string method_name = "recv_data";

    // Устанавливаем таймаут ожидания получения данных
    timeout.tv_sec = 10;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));

    std::chrono::milliseconds duration(10);
    int rc = 0;

    std::cout << "[INFO] " << method_name << " | Ожидаем данные от сервера..." << std::endl;

    // Пытаемся получить данные от сервера
    while (true)
    {
        // Выделяем новый буфер
        buffer = std::unique_ptr<char[]>(new char[buflen]);
        std::this_thread::sleep_for(duration); // Небольшая задержка перед чтением

        // MSG_PEEK — читаем данные, но не удаляем их из очереди
        rc = recv(sock, buffer.get(), buflen, MSG_PEEK);

        if (rc == 0)
        {
            // Сервер закрыл соединение
            std::cerr << "[ERROR] " << method_name << " | Принято 0 байт от сервера. Закрываем сокет." << std::endl;
            close_sock();
            debugger.show_error_information("Ошибка в recv_data()", "Принято 0 байт от сервера", "Логическая ошибка");
            return "";
        }
        else if (rc < 0)
        {
            // Произошла ошибка при приеме
            std::cerr << "[ERROR] " << method_name << " | Ошибка при получении данных: recv() вернуло " << rc << std::endl;
            close_sock();
            debugger.show_error_information("Ошибка в recv_data()", "Результат recv = -1", "Логическая ошибка");
            return "";
        }

        if (rc < buflen)
            break; // Данные успешно помещаются в буфер, можно продолжить

        // Если буфер переполнен, увеличиваем его размер
        buflen *= 2;
        std::cout << "[INFO] " << method_name << " | Увеличиваем буфер до " << buflen << " байт." << std::endl;
    }

    // Формируем строку из принятых данных
    std::string msg(buffer.get(), rc);

    std::this_thread::sleep_for(duration); // Небольшая задержка

    // MSG_TRUNC используется здесь ошибочно — он не работает с нулевым указателем
    if (recv(sock, nullptr, rc, MSG_TRUNC) < 0)
    {
        std::cerr << "[ERROR] " << method_name << " | Ошибка при подтверждении получения данных (MSG_TRUNC)." << std::endl;
        close_sock();
        debugger.show_error_information("Ошибка в recv_data()", "Результат recv = -1", "Логическая ошибка");
        return "";
    }

    std::cout << "[INFO] " << method_name << " | Данные успешно получены от сервера. Размер данных: " << rc << " байт." << std::endl;

    return msg;
}
void client::close_sock()
{
    std::cout << "[INFO] Закрытие сокета клиента..." << std::endl;

    // Пытаемся закрыть сокет
    if (close(sock) == 0)
    {
        std::cout << "[INFO] Сокет клиента успешно закрыт" << std::endl;
    }
    else
    {
        // Если возникла ошибка при закрытии
        std::cerr << "[ERROR] Ошибка при закрытии сокета клиента" << std::endl;
    }
}
void client::send_data(std::string data)
{
    std::chrono::milliseconds duration(10);

    // Создаем временный буфер и копируем в него строку для отправки
    std::unique_ptr<char[]> temp{new char[data.length() + 1]};
    strcpy(temp.get(), data.c_str());

    // Передаем временный буфер в основной, чтобы он жил до завершения send
    buffer = std::move(temp);

    // Небольшая задержка, возможно, для разгрузки CPU или задержки между отправками
    std::this_thread::sleep_for(duration);

    // Отправляем данные на сервер
    int sb = send(sock, buffer.get(), data.length(), 0);

    if (sb < 0)
    {
        // Обработка ошибки отправки
        std::cerr << "[ERROR] Ошибка отправки данных строкового типа" << std::endl;
        close_sock();
        debugger.show_error_information("Ошибка в send_data() - string", "Результат send = -1", "Логическая ошибка");
        return;
    }

    // Подтверждение успешной отправки
    std::cout << "[INFO] Отправлены данные строкового типа: \"" << data << "\" (Размер: " << data.length() << " байт)" << std::endl;
}
std::vector<std::string> client::recv_vector()
{
    // Установка таймаута для приёма данных: 10 секунд
    timeout.tv_sec = 10;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));

    std::vector<std::string> received_vector;
    std::chrono::milliseconds duration(10); // Пауза между операциями (опционально)

    // Получаем количество строк в векторе
    uint32_t vec_size = 0;
    std::this_thread::sleep_for(duration);

    if (recv(sock, &vec_size, sizeof(vec_size), 0) <= 0)
    {
        std::cerr << "[ERROR] Ошибка при получении размера вектора" << std::endl;
        close_sock();
        debugger.show_error_information("Ошибка в recv_vector()", "Возможная причина - ошибка на стороне сервера при отправке размера вектора", "Логическая ошибка");
        return received_vector; // Возвращаем пустой вектор в случае ошибки
    }

    vec_size = ntohl(vec_size); // Переводим байты в порядок хоста (big endian -> little endian)
    std::cout << "[INFO] Получен размер вектора: " << vec_size << " элементов" << std::endl;

    // Принимаем строки по одной
    for (uint32_t i = 0; i < vec_size; ++i)
    {
        uint32_t str_size = 0;
        std::this_thread::sleep_for(duration);

        // Получаем длину очередной строки
        if (recv(sock, &str_size, sizeof(str_size), 0) <= 0)
        {
            std::cerr << "[ERROR] Ошибка при получении размера строки #" << i + 1 << std::endl;
            debugger.show_error_information("Ошибка в recv_vector()", "Возможная причина - ошибка на стороне сервера при отправке размера строки", "Логическая ошибка");
            close_sock();
            return received_vector;
        }

        str_size = ntohl(str_size); // Конвертируем размер строки из сетевого порядка байтов

        std::this_thread::sleep_for(duration);

        // Создаем буфер под строку и принимаем строку
        std::unique_ptr<char[]> buffer(new char[str_size + 1]);

        if (recv(sock, buffer.get(), str_size, 0) <= 0)
        {
            std::cerr << "[ERROR] Ошибка при получении строки #" << i + 1 << std::endl;
            debugger.show_error_information("Ошибка в recv_vector()", "Возможная причина - ошибка на стороне сервера при отправке строки", "Логическая ошибка");
            close_sock();
            return received_vector;
        }

        buffer[str_size] = '\0'; // Добавляем терминальный символ конца строки

        // Сохраняем строку в вектор
        received_vector.emplace_back(buffer.get());
    }

    std::cout << "[INFO] Вектор успешно получен, количество строк: " << received_vector.size() << std::endl;
    return received_vector;
}
void client::print_vector(const std::vector<std::string> &vec)
{
    // Если вектор пустой, сообщаем об этом и выходим
    if (vec.empty())
    {
        std::cout << "[INFO] Список файлов пуст." << std::endl;
        return;
    }

    // Вывод заголовка
    std::cout << "[INFO] Список файлов:" << std::endl;
    std::cout << "-----------------------------" << std::endl;

    // Перебор и форматированный вывод всех строк
    for (size_t i = 0; i < vec.size(); ++i)
    {
        std::cout << std::setw(3) << i + 1 << ". " // Нумерация с выравниванием
                  << std::left << std::setw(40)    // Выравнивание строки по левому краю, ширина 40
                  << vec[i] << std::endl;          // Сама строка
    }

    // Завершающий разделитель
    std::cout << "-----------------------------" << std::endl;

    // Информация о количестве строк
    std::cout << "[INFO] Общее количество файлов: " << vec.size() << std::endl;
}
int client::recv_file(std::string &file_path)
{
    // Устанавливаем таймаут на получение данных по сокету (10 секунд)
    timeout.tv_sec = 10;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));

    // Открытие файла для бинарной записи
    std::ofstream file(file_path, std::ios::binary);
    if (!file)
    {
        std::cerr << "[ERROR] Ошибка открытия файла для записи!" << std::endl;
        return 1;
    }

    // Получаем размер файла (8 байт, big-endian)
    int64_t file_size_net = 0;
    int received = recv(sock, &file_size_net, sizeof(file_size_net), MSG_WAITALL);
    if (received != sizeof(file_size_net))
    {
        std::cerr << "[ERROR] Не удалось получить размер файла!" << std::endl;
        file.close();
        debugger.show_error_information("Ошибка в recv_file()", "Не удалось открыть файл для записи", "Логическая ошибка");
        return 1;
    }

    // Преобразуем размер файла в хост-байтовый порядок
    int64_t file_size = be64toh(file_size_net);
    std::cout << "[INFO] Размер файла к получению: " << file_size << " байт" << std::endl;

    // Буфер фиксированного размера (128 КБ)
    constexpr size_t BUFFER_SIZE = 262144;
    std::vector<char> buffer(BUFFER_SIZE);

    // Переменные для отслеживания прогресса
    int64_t total_bytes_received = 0;
    int block_count = 0;

    // Основной цикл приёма данных
    while (total_bytes_received < file_size)
    {
        // Сколько ещё байт нужно получить (но не больше размера буфера)
        size_t to_receive = std::min(static_cast<int64_t>(BUFFER_SIZE), file_size - total_bytes_received);

        // Получаем порцию данных
        int bytes_received = recv(sock, buffer.data(), to_receive, 0);

        // Ошибка получения
        if (bytes_received < 0)
        {
            std::cerr << "[ERROR] Ошибка при получении данных!" << std::endl;
            file.close();
            debugger.show_error_information("Ошибка в recv_file()", "Возможная причина - ошибка на стороне сервера", "Логическая ошибка");
            return 1;
        }

        // Сервер закрыл соединение раньше времени
        if (bytes_received == 0)
        {
            std::cerr << "[ERROR] Сервер преждевременно закрыл соединение!" << std::endl;
            file.close();
            debugger.show_error_information("Ошибка в recv_file()", "Сервер закрыл соединение в ходе передачи", "Логическая ошибка");
            return 1;
        }

        // Записываем данные в файл
        file.write(buffer.data(), bytes_received);

        // Обновляем количество полученных байт
        total_bytes_received += bytes_received;

        // Выводим прогресс
        std::cout << "[INFO] Принят блок #" << ++block_count << ", размер: " << bytes_received << " байт" << std::endl;
        std::cout << "[INFO] Принято данных: " << total_bytes_received << "/" << file_size << " байт" << std::endl;
    }

    // Закрываем файл
    file.close();
    std::cout << "[INFO] Файл успешно принят! Общий размер: " << total_bytes_received << " байт" << std::endl;

    return 0;
}
std::string client::hash_gen(std::string password)
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
