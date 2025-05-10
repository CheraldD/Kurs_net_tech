#pragma once

#include <QMainWindow>
#include <QLineEdit>
#include <QLabel>
#include <QPushButton>
#include <QTextEdit>
#include <QScrollArea>
#include <QVBoxLayout>
#include <QMap>
#include <QGroupBox>
#include <QFormLayout>
#include <QThread>
#include "communicator.h"

class ServerWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit ServerWindow(QWidget *parent = nullptr);
    ~ServerWindow();

private:
    // UI для управления
    QLabel*      portLabel;
    QLineEdit*   portEdit;
    QLabel*      logLabel;
    QLineEdit*   logEdit;
    QPushButton* browseButton;
    QPushButton* startButton;
    QTextEdit*   logView;

    // Новый UI для клиентов
    QScrollArea*       clientArea;
    QWidget*           clientContainer;
    QVBoxLayout*       clientLayout;
    QMap<QString, QGroupBox*> clientBlocks;  // clientID → блок

    // Server objects
    communicator*      server;
    QThread*           serverThread;

private slots:
    void browseLogDir();
    void startServer();

    // слоты для сигналов communicator
    void onClientConnected(QString clientIP, QString clientID);
    void onClientDisconnected(QString clientID);
    void onMessageReceived(QString clientID, QString message);
    void onMessageSent(QString clientID, QString header, QString content);
    void onFileListSent(QString clientID, int fileCount);
    void onFileSent(QString clientID, QString filePath);
    void onClientAuthenticated(QString clientID, bool success);
    void onClientRegistered(QString clientID, bool success);
    void onLogEvent(QString context, QString message);
};
