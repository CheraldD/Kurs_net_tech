#ifndef SERVERWINDOW_H
#define SERVERWINDOW_H

#include <QMainWindow>
#include <QMap>
#include <QPushButton>
#include <QLineEdit>
#include <QTextEdit>
#include <QScrollArea>
#include <QGridLayout>
#include <QLabel>
#include <QGroupBox>
#include <QThread>

#include "communicator.h"

class ServerWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit ServerWindow(QWidget *parent = nullptr);
    ~ServerWindow();

private slots:
    void browseLogDir();
    void startServer();
    void stopServer();

    // Слоты сигналов от communicator
    void onClientConnected(QString clientIP, QString clientID);
    void onClientDisconnected(QString clientID);
    void onMessageReceived(QString clientID, QString message);
    void onMessageSent(QString clientID, QString header, QString content);
    void onFileListSent(QString clientID, int fileCount);
    void onFileSent(QString clientID, QString filePath);
    void onClientAuthenticated(QString clientID, bool success);
    void onClientRegistered(QString clientID, bool success);
    void onLogEvent(QString context, QString message);

    // Слот для переключения видимости логов
    void toggleLogVisibility();

private:
    QLineEdit *portEdit;
    QLineEdit *logEdit;
    QPushButton *browseButton;
    QPushButton *startButton;
    QPushButton *stopButton;

    QTextEdit *logView;
    QScrollArea *clientArea;
    QWidget *clientContainer;
    QGridLayout *clientLayout;

    communicator *server;
    QThread *serverThread;

    QMap<QString, QGroupBox*> clientBlocks;
    int clientCount = 0;

    // Новые переменные
    QGroupBox *logGroup;           // Группа для логов
    QPushButton *toggleLogButton;  // Кнопка для переключения видимости логов
};

#endif // SERVERWINDOW_H
