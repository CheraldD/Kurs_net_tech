#include "base.h"

base::base() {
    // Можно использовать connectToDatabase, чтобы подключить к базе данных при создании объекта.
    if (!connectToDatabase("client_base.db")) {
        qCritical() << "Не удалось подключиться к базе данных.";
    }
}

// Подключение к базе данных
bool base::connectToDatabase(const std::string& dbName) {
    db.setDatabaseName(QString::fromStdString(dbName));
    if (!db.open()) {
        printQueryError(query, "CONNECT");
        return false;
    }
    qDebug() << "Подключение к базе данных успешно.";
    return true;
}

// Функция для вставки нового пользователя в таблицу
bool base::insertUser(const std::string& username, const std::string& password, const std::string& ip) {
    query.prepare("INSERT INTO users (username, password, ip) VALUES (:username, :password, :ip)");
    query.bindValue(":username", QString::fromStdString(username));
    query.bindValue(":password", QString::fromStdString(password));
    query.bindValue(":ip", QString::fromStdString(ip));

    if (!query.exec()) {
        printQueryError(query, "INSERT");
        return false;
    }
    qDebug() << "Пользователь успешно добавлен.";
    return true;
}

// Функция для выбора пользователя по ID
bool base::selectUserByName(std::string name) {
    query.prepare("SELECT * FROM users WHERE username = :name");
    query.bindValue(":name", QString::fromStdString(name));

    if (!query.exec()) {
        printQueryError(query, "SELECT");
        return false;
    }

    if (query.next()) {
        int userId = query.value(0).toInt();
        QString username = query.value(1).toString();
        QString password = query.value(2).toString();
        QString ip = query.value(3).toString();

        // Сохраняем текущие значения
        current_ip_ = ip.toStdString();
        current_hashed_password_ = password.toStdString();

        qDebug() << "ID: " << userId << "Username: " << username << "Password: " << password << "IP: " << ip;
        return true;
    } else {
        qDebug() << "Пользователь не найден.";
        return false;
    }
}
std::string base::getCurrentIP() const {
    return current_ip_;
}

std::string base::getCurrentHashedPassword() const {
    return current_hashed_password_;
}

bool base::deleteUserByName(std::string name) {
     // Подготовка SQL-запроса для удаления пользователя по имени
     query.prepare("DELETE FROM users WHERE username = :name");
     query.bindValue(":name", QString::fromStdString(name));
 
     // Выполнение запроса
     if (!query.exec()) {
         printQueryError(query, "DELETE");
         return false;
     }
 
     qDebug() << "Пользователь с именем " << QString::fromStdString(name) << " удален.";
     return true;
}

// Функция для изменения данных пользователя по ID
bool base::alterUser(int id, const std::string& username, const std::string& password, const std::string& ip) {
    query.prepare("UPDATE users SET username = :username, password = :password, ip = :ip WHERE id = :id");
    query.bindValue(":id", id);
    query.bindValue(":username", QString::fromStdString(username));
    query.bindValue(":password", QString::fromStdString(password));
    query.bindValue(":ip", QString::fromStdString(ip));

    if (!query.exec()) {
        printQueryError(query, "UPDATE");
        return false;
    }
    qDebug() << "Данные пользователя с ID" << id << "обновлены.";
    return true;
}

// Функция для вывода ошибки SQL-запроса
void base::printQueryError(const QSqlQuery& query, const std::string& queryType) {
    qCritical() << "Ошибка SQL-запроса типа:" << QString::fromStdString(queryType)
                << "с сообщением:" << query.lastError().text();
}
