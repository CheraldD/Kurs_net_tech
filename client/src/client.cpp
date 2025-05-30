#include "client.h"
#include <sys/ioctl.h>
#include <net/if.h>
void client::work(UI &intf)
{
    const std::string method_name = "client::work";
    std::cout << "[INFO] [" << method_name << "] Начало работы клиента." << std::endl;

    // Получаем параметры из интерфейса пользователя
    serv_ip = intf.get_serv_ip().c_str();
    port = intf.get_port();
    op = intf.get_op();
    password = intf.get_password();
    id = intf.get_username();

    start();
    connect_to_server();
    if(recv_data("Ошибка при приеме флага заполненности сервера")=="Сервер полон"){
        close_sock();
        std::cout << "[INFO] [" << method_name << "] Сервер полон" << std::endl;
        exit(1);
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));

    // Отправляем тип операции (регистрация / аутентификация)
    send_data("OP", id, 0, std::to_string(op));

    if (op == 1)
    {
        std::cout << "[INFO] [" << method_name << "] Выполняется аутентификация клиента..." << std::endl;
        client_auth();
        std::cout << "[INFO] [" << method_name << "] Аутентификация успешна." << std::endl;
    }
    else
    {
        std::cout << "[INFO] [" << method_name << "] Выполняется регистрация клиента..." << std::endl;
        client_reg();
        std::cout << "[INFO] [" << method_name << "] Регистрация успешна." << std::endl;
    }

    // Получение списка файлов
    files = recv_vector();  // Оставляем как есть
    std::cout << "[INFO] [" << method_name << "] Получен список файлов с сервера:" << std::endl;
    print_vector(files);

    // Основной цикл
    while (true)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        std::string file_path, save_path;

        std::cout << "[INPUT] Введите путь к файлу данных: ";
        std::getline(std::cin, file_path);

        std::cout << "[INPUT] Введите путь для сохранения файла: ";
        std::getline(std::cin, save_path);

        if (file_path.empty() || save_path.empty())
        {
            std::cerr << "[WARN] [" << method_name << "] Путь не может быть пустым." << std::endl;
            continue;
        }

        // Отправляем путь к файлу
        std::cout << "[INFO] [" << method_name << "] Отправка пути к файлу на сервер: " << file_path << std::endl;
        send_data("REQ_FILE", id, 0, file_path);

        std::cout << "[INFO] [" << method_name << "] Получение файла с сервера..." << std::endl;
        if (recv_file(save_path) == 1)
        {
            std::cerr << "[ERROR] [" << method_name << "] Ошибка при получении файла: " << save_path << std::endl;
            continue;
        }

        std::cout << "[INFO] [" << method_name << "] Файл успешно получен: " << save_path << std::endl;
    }

    close_sock();
    std::cout << "[INFO] [" << method_name << "] Клиент завершил работу." << std::endl;
    exit(1);
}


void client::client_reg()
{
    const std::string method_name = "client::client_reg";

    std::cout << "[INFO] [" << method_name << "] Инициализация регистрации пользователя..." << std::endl;

    std::cout << "[INFO] [" << method_name << "] Генерация хэша пароля для отправки на сервер..." << std::endl;
    std::string hashed_password = hash_gen(password);

    std::cout << "[INFO] [" << method_name << "] Отправка хэшированного пароля на сервер..." << std::endl;
    send_data("REG_PASS", id, 0, hashed_password);

    std::cout << "[INFO] [" << method_name << "] Ожидание ответа от сервера..." << std::endl;
    std::string answ = recv_data("Ошибка при принятии ответа о регистрации с сервера");

    if (answ != "Регистрация успешна")
    {
        std::cout << "[ERROR] [" << method_name << "] Флаг ошибки: " << answ << std::endl;
        close_sock();
        debugger.show_error_information("Ошибка в client_reg()", "Возможная причина - ошибка запроса к БД на сервере", "Логическая ошибка");
        exit(1);
    }

    std::cout << "[INFO] [" << method_name << "] Регистрация завершена. Закрытие соединения." << std::endl;
    close_sock();

    std::cout << "[INFO] [" << method_name << "] Завершение работы клиента." << std::endl;
    exit(0);
}


void client::client_auth()
{
    const std::string method_name = "client::client_auth";
    std::chrono::milliseconds duration(30);

    std::cout << "[INFO] [" << method_name << "] Начало аутентификации..." << std::endl;
    std::this_thread::sleep_for(duration);

    // Отправка хэша пароля
    std::string hashed_password = hash_gen(password);
    std::cout << "[INFO] [" << method_name << "] Отправка хэшированного пароля..." << std::endl;
    send_data("AUTH_PASS", id, 0, hashed_password);
    std::this_thread::sleep_for(duration);

    // Отправка IP-адреса клиента
    std::cout << "[INFO] [" << method_name << "] Отправка IP-адреса клиента..." << std::endl;
    send_data( "AUTH_IP", id, 0, ip);
    std::this_thread::sleep_for(duration);

    // Получение ответа от сервера
    std::cout << "[INFO] [" << method_name << "] Ожидание ответа от сервера..." << std::endl;
    std::string flag = recv_data("Ошибка при принятии ответа о аутентификации с сервера");

    if (flag != "Аутентификация успешна")
    {
        std::cout << "[ERROR] [" << method_name << "] Флаг ошибки: " << flag << std::endl;
        debugger.show_error_information("Ошибка в client_auth()", "UERR - неверное имя пользователя \nPERR - неверный пароль \nIERR - неверный айпи", "Логическая ошибка");
        close_sock();
        exit(1);
    }

    std::cout << "[INFO] [" << method_name << "] Аутентификация завершена успешно." << std::endl;
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
    const std::string method_name = "client::connect_to_server";
    std::cout << "[INFO] [" << method_name << "] Получаем информацию о локальном сокете..." << std::endl;
    sockaddr_in localAddr{};
    socklen_t addrLen = sizeof(localAddr);

    // Получаем локальный адрес сокета
    if (getsockname(sock, (struct sockaddr *)&localAddr, &addrLen) < 0)
    {
        std::cerr << "[ERROR] [" << method_name << "] Ошибка получения информации о сокете" << std::endl;
        return;
    }
    std::cout << "[INFO] [" << method_name << "] Локальный адрес сокета получен: " << inet_ntoa(localAddr.sin_addr) << std::endl;

    // Проверка, если IP сервера равен 127.0.0.1 (локальный сервер)
    if (serverAddr.sin_addr.s_addr == htonl(INADDR_LOOPBACK))
    {
        ip = "127.0.0.1"; // Если сервер локальный
        std::cout << "[INFO] [" << method_name << "] Сервер локальный. Используется IP: 127.0.0.1" << std::endl;
    }
    else
    {
	struct ifreq ifr;
	strncpy(ifr.ifr_name,"enp4s0",IFNAMSIZ-1);
	if(ioctl(sock,SIOCGIFADDR,&ifr)==-1){
		perror("ioctl");
		close(sock);
		return;
	}
	char ipp[INET_ADDRSTRLEN];
	inet_ntop(AF_INET,&((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr,ipp,sizeof(ipp));
	ip=ipp;
        std::cout << "[INFO] [" << method_name << "] Сервер не локальный. Используется IP: " << ip << std::endl;
    }

    // Пытаемся подключиться к серверу
    std::cout << "[INFO] [" << method_name << "] Пытаемся подключиться к серверу..." << std::endl;
    if (connect(sock, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0)
    {
        close_sock();
        std::cerr << "[ERROR] [" << method_name << "] Ошибка подключения к серверу. Проверьте IP или порт." << std::endl;
        debugger.show_error_information("Ошибка в connect_to_server()", "Возможная причина - неверный айпи или порт сервера", "Логическая ошибка");
        return;
    }

    std::cout << "[INFO] [" << method_name << "] Клиент успешно подключился к серверу" << std::endl;

    // Отправляем идентификатор клиента с заголовком
    std::cout << "[INFO] [" << method_name << "] Отправляем идентификатор клиента: " << id << std::endl;
    send_data( "CLIENT_ID", id, 0, id);
}
// (send_data unchanged above)

std::string client::recv_data(std::string error_msg)
{
    const std::string method_name = "recv_data";

    // Устанавливаем таймаут на приём данных
    timeout.tv_sec = 100;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));

    // 1) Принять пакет LENGTH, содержащий размер следующего DATA-пакета
    std::vector<char> len_buf(buflen);
    int len_bytes = recv(sock, len_buf.data(), buflen, 0);
    if (len_bytes <= 0) {
        //close_sock();
        std::cerr << "[ERROR] [" << method_name << "] " << error_msg << " (LENGTH)" << std::endl;
        return "";
    }
    // распарсить LENGTH-пакет целиком
    std::string len_raw(len_buf.data(), len_bytes);
    MessageProtocol::ParsedMessage len_msg;
    try {
        len_msg = MessageProtocol::parse(len_raw);
    } catch (const std::exception &e) {
        std::cerr << "[ERROR] [" << method_name << "] Ошибка парсинга LENGTH: " << e.what() << std::endl;
        return "";
    }
    int payload_size = 0;
    try {
        payload_size = std::stoi(len_msg.message);
    } catch (...) {
        std::cerr << "[ERROR] [" << method_name << "] Неверный размер payload: " << len_msg.message << std::endl;
        return "";
    }

    // 2) Принять DATA-пакет указанного размера
    std::vector<char> data_buf;
    data_buf.reserve(payload_size);
    int total = 0;
    while (total < payload_size) {
        int to_read = std::min(buflen, payload_size - total);
        int r = recv(sock, len_buf.data(), to_read, 0);
        if (r <= 0) {
            //close_sock();
            std::cerr << "[ERROR] [" << method_name << "] " << error_msg << " (DATA)" << std::endl;
            return "";
        }
        data_buf.insert(data_buf.end(), len_buf.data(), len_buf.data() + r);
        total += r;
    }

    // распарсить DATA-пакет
    std::string data_raw(data_buf.data(), data_buf.size());
    try {
        auto pm = MessageProtocol::parse(data_raw);
        return pm.message;
    } catch (const std::exception &e) {
        std::cerr << "[ERROR] [" << method_name << "] Ошибка парсинга DATA: " << e.what() << std::endl;
        return "";
    }
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
void client::send_data(const std::string& header,
                             const std::string& client_id, int message_id,
                             const std::string& msg)
{
    const std::string method_name = "send_data";

    if (sock < 0) {
        std::cerr << "[ERROR] [" << method_name << "] Некорректный сокет сервера" << std::endl;
        return;
    }

    std::cout << "[INFO] [" << method_name << "] Подготовка отправки данных серверу" << std::endl;

    std::string packet = MessageProtocol::build(header, client_id, message_id, msg);

    std::this_thread::sleep_for(std::chrono::milliseconds(10)); // пауза

    size_t total_sent = 0;
    while (total_sent < packet.size()) {
        int sent_now = send(sock, packet.c_str() + total_sent, packet.size() - total_sent, 0);
        if (sent_now <= 0) {
            std::cerr << "[ERROR] [" << method_name << "] Ошибка отправки серверу данных" << std::endl;
            close_sock();
            return;
        }
        total_sent += sent_now;
    }

    std::cout << "[INFO] [" << method_name << "] Успешно отправлено " << total_sent << " байт серверу " << std::endl;
}
std::vector<std::string> client::recv_vector()
{
    const std::string method_name = "client::recv_vector";
    std::vector<std::string> received_vector;

    // Получаем количество элементов в векторе через протокол
    std::cout << "[INFO] [" << method_name << "] Ожидание заголовка FILE_COUNT..." << std::endl;
    std::string count_str = recv_data("Ошибка при приеме количества файлов");
    if (count_str.empty()) {
        std::cerr << "[ERROR] [" << method_name << "] Не удалось получить количество элементов." << std::endl;
        return received_vector;
    }

    int32_t vec_size = 0;
    try {
        vec_size = std::stoi(count_str);
    } catch (const std::exception& e) {
        std::cerr << "[ERROR] [" << method_name << "] Неверный формат размера вектора: " << count_str << std::endl;
        return received_vector;
    }
    std::cout << "[INFO] [" << method_name << "] Получено FILE_COUNT = " << vec_size << std::endl;

    // Принимаем каждую запись FILE_ENTRY
    for (int32_t i = 0; i < vec_size; ++i)
    {
        std::cout << "[INFO] [" << method_name << "] Ожидание заголовка FILE_ENTRY #" << (i+1) << "..." << std::endl;
        std::string entry = recv_data("Ошибка при приеме имени файла");
        if (entry.empty()) {
            std::cerr << "[ERROR] [" << method_name << "] Не удалось получить запись #" << (i+1) << std::endl;
            break;
        }
        std::cout << "[INFO] [" << method_name << "] Получен FILE_ENTRY #" << (i+1) << ": " << entry << std::endl;
        received_vector.push_back(entry);
    }

    std::cout << "[INFO] [" << method_name << "] Вектор успешно собран, элементов: " << received_vector.size() << std::endl;
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
    const std::string method_name = "client::recv_file";

    // Открываем файл для записи
    std::ofstream file(file_path, std::ios::binary);
    if (!file)
    {
        std::cerr << "[ERROR] [" << method_name << "] Ошибка открытия файла для записи: " << file_path << std::endl;
        return 1;
    }

    // Получаем из протокола размер файла (HEADER = "FILE_SIZE")
    std::cout << "[INFO] [" << method_name << "] Ожидание HEADER=FILE_SIZE..." << std::endl;
    std::string size_str = recv_data("Ошибка при приеме размера файла с сервера");
    if (size_str.empty() or size_str=="Файл не найден" or size_str=="Ошибка открытия файла")
    {
        std::cerr << "[ERROR] [" << method_name << "] Не удалось получить размер файла." <<"Флаг ошибки: "<< size_str<< std::endl;
        file.close();
        return 1;
    }

    int64_t file_size = 0;
    try {
        file_size = std::stoll(size_str);
    }
    catch (const std::exception &e) {
        std::cerr << "[ERROR] [" << method_name << "] Неверный формат размера файла: " << size_str << std::endl;
        file.close();
        return 1;
    }
    std::cout << "[INFO] [" << method_name << "] Размер файла к получению: " << file_size << " байт" << std::endl;

    // Принимаем чанки до HEADER = "FILE_END"
    int64_t total_received = 0;
    int block_index = 0;
    while (true)
    {
        std::cout << "[INFO] [" << method_name << "] Ожидание следующего HEADER..." << std::endl;
        std::string chunk = recv_data("Ошибка при приеме чанка файла");
        if (chunk.empty())
        {
            std::cerr << "[ERROR] [" << method_name << "] Ошибка при получении чанка файла." << std::endl;
            file.close();
            return 1;
        }

        // Признак конца передачи
        if (chunk == "EOF")
        {
            std::cout << "[INFO] [" << method_name << "] Получен HEADER=FILE_END." << std::endl;
            break;
        }

        // Записываем бинарные данные чанка
        file.write(chunk.data(), chunk.size());
        total_received += chunk.size();
        std::cout << "[INFO] [" << method_name << "] Принят блок #" << block_index++
                  << ", размер: " << chunk.size() << " байт (всего: " << total_received << "/" << file_size << ")" << std::endl;
    }

    file.close();

    if (total_received != file_size)
    {
        std::cerr << "[WARN] [" << method_name << "] Получено байт " << total_received
                  << ", ожидалось " << file_size << std::endl;
    }
    else
    {
        std::cout << "[INFO] [" << method_name << "] Файл успешно принят! Общий размер: "
                  << total_received << " байт" << std::endl;
    }

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
