/** @file
 * @author Стригин А.В.
 * @version 1.0
 * @date 23.12.2023
 * @copyright ИБСТ ПГУ
 * @brief Исполняемый файл для модуля communicator*/
#include "communicator.h"

int communicator::connect_to_cl(int &new_socket) {
    if (listen(serverSocket, 10) != 0) {
        log.write_log(log_location, "Ошибка при прослушивании порта");
        throw critical_error("Сервер не встал на прослушку");
    }

    log.write_log(log_location, "Сервер слушает");
    addr_size = sizeof(clientAddr);
    new_socket = accept(serverSocket, (struct sockaddr *)&clientAddr, &addr_size);
    if (new_socket < 0) {
        log.write_log(log_location, "Ошибка принятия соединения");
        return -1;
    }

    log.write_log(log_location, "Соединение установлено");
    return 0;
}

int communicator::authentification(int client_socket, std::string cl_id) {
    if (db.selectUserByName(cl_id) == 0) {
        close_sock(client_socket);
        return 0;
    }

    std::string cl_passw_base = db.getCurrentHashedPassword();
    std::string cl_ip_base = db.getCurrentIP();
    
    std::string cl_passw_recv = recv_data(client_socket, "Ошибка при приеме пароля");
    std::string cl_ip_recv = recv_data(client_socket, "Ошибка при приеме айпи");

    if (cl_passw_base != cl_passw_recv) {
        close_sock(client_socket);
        std::cout << "Неверный пароль клиента" << std::endl;
        return 0;
    }

    if (cl_ip_base != cl_ip_recv) {
        close_sock(client_socket);
        std::cout << "Неверный Айпи клиента" << std::endl;
        return 0;
    }
    return 1;
}

void communicator::registration(int client_socket, std::string cl_id) {
    std::string password = recv_data(client_socket, "Ошибка при приеме пароля");
    char client_ip_cstr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(clientAddr.sin_addr), client_ip_cstr, INET_ADDRSTRLEN);
    std::string client_ip_str = client_ip_cstr;
    
    db.insertUser(cl_id, password, client_ip_str);
    send_data(client_socket, "Аутентификация успешна", "Ошибка отправки отладочного сообщения");
    close_sock(client_socket);
}

communicator::communicator(uint port, std::string base_loc, std::string log_loc)
{
    p = port;
    base_location = base_loc;
    log_location = log_loc;
}
void communicator::work() {
    start();
    while (true) {
        int new_socket;
        if (connect_to_cl(new_socket) == 0) {
            std::thread client_thread(&communicator::handle_client, this, new_socket);
            client_thread.detach();
        }
    }
}
void communicator::handle_client(int client_socket) {
    try {
        // Получаем ID клиента
        std::string cl_id = recv_data(client_socket, "Ошибка при приеме айди клиента");
        std::string operation_type = recv_data(client_socket, "Ошибка приема типа операции");

        // Делаем небольшую паузу для синхронизации
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        std::cout << "Получен тип операции: " << operation_type << std::endl;

        if (operation_type == "0") {
            registration(client_socket, cl_id);
        } else {
            if (authentification(client_socket, cl_id) == 0) {
                return;
            }
            std::cout << "Подсоединился пользователь: " + cl_id << std::endl;
        }

        // Обработка файлов
        file_exchange(client_socket);
    } catch (const std::exception &e) {
        log.write_log(log_location, std::string("Ошибка в обработке клиента: ") + e.what());
        close_sock(client_socket);
    }
}

void communicator::start(){
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
}
int communicator::file_exchange(int client_socket) {
    send_file_list(client_socket);

    while (true) {
        std::string path = recv_data(client_socket,"Ошибка при принятии пути к запрашиваемому файлу");
        
        if (path.empty()) {
            std::cerr << "Ошибка при приеме имени файла от клиента/клиент закрыл соединение" << std::endl;
            close_sock(client_socket);
            return 1;
        }

        if (send_file(client_socket, path) == 1) {
            std::cerr << "Ошибка при отправке файла клиенту" << std::endl;
            close_sock(client_socket);
            return 1;
        }
    }
    return 0;
}
std::string communicator::recv_data(int client_socket, std::string messg) {
    timeout.tv_sec = 100;
    timeout.tv_usec = 0;
    setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));

    int rc = 0;
    size_t peek_buflen = buflen;
    std::vector<char> temp_buffer(peek_buflen);

    while (true) {
        rc = recv(client_socket, temp_buffer.data(), peek_buflen, MSG_PEEK);
        if (rc == 0) {
            close_sock(client_socket);
            log.write_log(log_location, "Клиент закрыл соединение");
            return "";
        } else if (rc < 0) {
            close_sock(client_socket);
            log.write_log(log_location, messg);
            return "";
        }

        if (static_cast<size_t>(rc) < peek_buflen) break;
        peek_buflen *= 2;
        temp_buffer.resize(peek_buflen);
    }

    std::string msg(temp_buffer.data(), rc);
    if (recv(client_socket, nullptr, rc, MSG_TRUNC) <= 0) {
        close_sock(client_socket);
        log.write_log(log_location, messg);
        return "";
    }

    std::cout << "Строка принята: " << msg << std::endl;
    return msg;
}


void communicator::send_data(int client_socket, std::string data, std::string msg) {
    std::chrono::milliseconds duration(10);
    std::unique_ptr<char[]> temp{new char[data.length() + 1]};
    strcpy(temp.get(), data.c_str());
    buffer = std::move(temp);
    std::this_thread::sleep_for(duration);

    int sb = send(client_socket, buffer.get(), data.length(), 0);
    if (sb <= 0) {
        log.write_log(log_location, msg);
        close_sock(client_socket);
    }
}

void communicator::close_sock(int client_socket) {
    close(client_socket);
    log.write_log(log_location, "Разорвано соединение с клиентом");
}

void communicator::send_file_list(int client_socket) {
    std::chrono::milliseconds duration(10);
    data_handler handler;
    std::vector<std::string> files = handler.get_file_list();
    if (files.empty()) {
        std::cerr << "Отправка вектора: список файлов пуст!" << std::endl;
        return;
    }

    uint32_t vector_size = htonl(files.size());
    std::this_thread::sleep_for(duration);
    if (send(client_socket, &vector_size, sizeof(vector_size), 0) <= 0) {
        close_sock(client_socket);
        std::cerr << "Ошибка отправки размера вектора" << std::endl;
        return;
    }

    for (const auto& file : files) {
        uint32_t length = htonl(file.size());

        std::this_thread::sleep_for(duration);
        if (send(client_socket, &length, sizeof(length), 0) <= 0) {
            close_sock(client_socket);
            std::cerr << "Ошибка отправки размера строки" << std::endl;
            return;
        }

        std::this_thread::sleep_for(duration);
        if (send(client_socket, file.c_str(), file.size(), 0) <= 0) {
            close_sock(client_socket);
            std::cerr << "Ошибка отправки данных строки" << std::endl;
            return;
        }
    }
}

int communicator::send_file(int client_socket, std::string& file_path) {
    if (!boost::filesystem::exists(file_path)) {
        std::cout << "Такого запрашиваемого файла не существует" << std::endl;
        close_sock(client_socket);
        return 1;
    }

    std::ifstream file(file_path, std::ios::binary | std::ios::ate);
    if (!file) {
        std::cerr << "Ошибка открытия файла!" << std::endl;
        close_sock(client_socket);
        return 1;
    }

    std::streamsize file_size = file.tellg();
    file.seekg(0, std::ios::beg);

    int64_t size_net = htobe64(static_cast<int64_t>(file_size));
    if (send(client_socket, &size_net, sizeof(size_net), 0) <= 0) {
        std::cerr << "Ошибка отправки размера файла!" << std::endl;
        close_sock(client_socket);
        return 1;
    }

    constexpr size_t BUFFER_SIZE = 65536;
    std::vector<char> buffer(BUFFER_SIZE);

    int total_bytes_sent = 0;
    int i = 0;

    while (file) {
        file.read(buffer.data(), BUFFER_SIZE);
        std::streamsize bytes_read = file.gcount();
        if (bytes_read <= 0) break;

        int bytes_sent = 0;
        while (bytes_sent < bytes_read) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            int sent = send(client_socket, buffer.data() + bytes_sent, bytes_read - bytes_sent, 0);
            if (sent <= 0) {
                std::cerr << "Ошибка отправки данных!" << std::endl;
                close_sock(client_socket);
                file.close();
                return 1;
            }
            bytes_sent += sent;
        }

        total_bytes_sent += bytes_sent;
        std::cout << "Отправлен блок #" << ++i << ", размер: " << bytes_sent << " байт" << std::endl;
    }

    file.close();
    std::cout << "Файл успешно отправлен! Общий размер: " << total_bytes_sent << " байт" << std::endl;
    return 0;
}



std::string communicator::hash_gen(std::string &password) {
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