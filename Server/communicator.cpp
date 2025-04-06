/** @file
 * @author Стригин А.В.
 * @version 1.0
 * @date 23.12.2023
 * @copyright ИБСТ ПГУ
 * @brief Исполняемый файл для модуля communicator*/
#include "communicator.h"

int communicator::connect_to_cl()
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
    std::chrono::milliseconds duration(10);
    std::this_thread::sleep_for(duration);
    std::string operation_type = recv_data("Ошибка приема типа операции");
    std::cout << "Получен тип операции: " << operation_type << std::endl;
    if (operation_type == "0") {
        registration(cl_id);
        return 0;
    }
    else{
        if(authentification(cl_id)==0){
            return 0;
        }
        std::cout << "Подсоединился пользователь: " + cl_id << std::endl;
    }
    return 1;
}
int communicator::authentification(std::string cl_id){
    std::chrono::milliseconds duration(10);
    if(db.selectUserByName(cl_id)==0){
        close_sock();
        return 0;
    }
    std::string cl_passw_base=db.getCurrentHashedPassword();
    std::string cl_ip_base=db.getCurrentIP();
    std::this_thread::sleep_for(duration);
    std::string cl_passw_recv = recv_data("Ошибка при приеме пароля");
    std::this_thread::sleep_for(duration);
    std::string cl_ip_recv = recv_data("Ошибка при приеме айпи");
    std::this_thread::sleep_for(duration);
    if(cl_passw_base!=cl_passw_recv){
        close_sock();
        std::cout<<"Неверный пароль клиента"<<std::endl;
        return 0;
    }
    if(cl_ip_base!=cl_ip_recv){
        close_sock();
        std::cout<<"Неверный Айпи клиента"<<std::endl;
        return 0;
    }
    return 1;
}
void communicator::registration(std::string cl_id){
    std::string password = recv_data("Ошибка при приеме пароля");
    char client_ip_cstr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(clientAddr.sin_addr), client_ip_cstr, INET_ADDRSTRLEN);
    std::string client_ip_str = client_ip_cstr;
    db.insertUser(cl_id,password,client_ip_str);
    send_data("Аутентификация успешна","Ошибка отправки отладочного сообщения");
    close_sock();
}
communicator::communicator(uint port, std::string base_loc, std::string log_loc)
{
    p = port;
    base_location = base_loc;
    log_location = log_loc;
}
void communicator::work()
{
    start();
    while(true){
    if(connect_to_cl()==0){
        continue;
    }
    send_file_list();
    file_exchange();
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
void communicator::file_exchange(){
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
    std::cout << "Строка принята: "<<msg << std::endl;
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

    // Увеличиваем размер буфера (64 KB = 65536 байт)
    constexpr size_t BUFFER_SIZE = 65536;
    std::vector<char> buffer(BUFFER_SIZE);

    size_t total_bytes_sent = 0;
    int i = 0;

    while (file)
    {
        file.read(buffer.data(), BUFFER_SIZE);
        std::streamsize bytes_read = file.gcount();
        if (bytes_read <= 0) break;

        size_t bytes_sent = 0;
        while (bytes_sent < bytes_read)
        {
            std::chrono::milliseconds duration(10);
            std::this_thread::sleep_for(duration);
            ssize_t sent = send(clientSocket, buffer.data() + bytes_sent, bytes_read - bytes_sent, 0);
            if (sent <= 0)
            {
                std::cerr << "Ошибка отправки данных!" << std::endl;
                file.close();
                return;
            }
            bytes_sent += sent;
        }

        total_bytes_sent += bytes_sent;
        std::cout << "Отправлен блок #" << ++i << ", размер: " << bytes_sent << " байт" << std::endl;
    }

    // Отправка сигнала конца файла
    char end_signal = 0;
    ssize_t sent = send(clientSocket, &end_signal, sizeof(end_signal), 0);
    if (sent <= 0)
    {
        std::cerr << "Ошибка отправки сигнала конца файла!" << std::endl;
        file.close();
        return;
    }

    file.close();
    std::cout << "Файл успешно отправлен! Общий размер: " << total_bytes_sent << " байт" << std::endl;
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