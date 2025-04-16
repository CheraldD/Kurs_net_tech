#include "logger.h"
int logger::write_log(std::string log_loc, std::string message) {
    // Проверяем, существует ли лог-файл по указанному пути
    if (!boost::filesystem::exists(log_loc)) {
        std::cout << "Такого лог файла не существует" << std::endl;
        throw critical_error("Не удалось открыть лог файл");
    }

    // Открываем файл для дозаписи
    log.open(log_loc, std::ios::app | std::ios::out);

    // Получаем текущее время
    auto now = std::chrono::system_clock::now();
    std::time_t end_time = std::chrono::system_clock::to_time_t(now);
    std::string time = std::ctime(&end_time);

    // Убираем символ новой строки в конце времени
    time.pop_back();

    // Блокируем мьютекс для предотвращения конфликтов при записи в лог
    mtx.lock();
    // Записываем время и сообщение в лог-файл
    log << time << " / " << message << '\n';
    // Освобождаем мьютекс
    mtx.unlock();

    // Сразу записываем в файл, не ожидая
    log.flush();
    // Закрываем файл после записи
    log.close();

    return 0;
}
