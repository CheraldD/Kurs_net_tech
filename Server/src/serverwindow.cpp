#include "serverwindow.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFileDialog>
#include <QDateTime>
#include <QGroupBox>
#include <QFormLayout>
#include <QSpacerItem>

ServerWindow::ServerWindow(QWidget *parent)
    : QMainWindow(parent),
      server(nullptr),
      serverThread(nullptr)
{
    auto central = new QWidget;
    auto mainLay = new QVBoxLayout(central);

    // Секция настроек сервера
    auto settingsGroup = new QGroupBox("Server Settings");
    auto settingsLay = new QFormLayout;

    portEdit = new QLineEdit("33333");
    settingsLay->addRow("Port:", portEdit);

    auto logLay = new QHBoxLayout;
    logEdit = new QLineEdit("log.txt");
    browseButton = new QPushButton("Browse...");
    logLay->addWidget(logEdit);
    logLay->addWidget(browseButton);
    settingsLay->addRow("Log Directory:", logLay);

    settingsGroup->setLayout(settingsLay);
    mainLay->addWidget(settingsGroup);

    // Кнопки запуска/остановки сервера
    auto controlGroup = new QGroupBox("Control");
    auto controlLay = new QHBoxLayout;
    startButton = new QPushButton("Start Server");
    stopButton = new QPushButton("Stop Server");
    stopButton->setEnabled(false);
    controlLay->addWidget(startButton);
    controlLay->addWidget(stopButton);
    controlGroup->setLayout(controlLay);
    mainLay->addWidget(controlGroup);

    // Список клиентов
    auto clientsGroup = new QGroupBox("Connected Clients");
    auto clientsLay = new QVBoxLayout;
    clientArea = new QScrollArea;
    clientContainer = new QWidget;
    clientLayout = new QGridLayout;
    clientContainer->setLayout(clientLayout);
    clientArea->setWidget(clientContainer);
    clientArea->setWidgetResizable(true);
    clientsLay->addWidget(clientArea);
    clientsGroup->setLayout(clientsLay);
    mainLay->addWidget(clientsGroup, 1); // растягивается

    // Просмотр логов
    logGroup = new QGroupBox("Event Log");
    auto logLayBox = new QVBoxLayout;
    logView = new QTextEdit;
    logView->setReadOnly(true);
    logLayBox->addWidget(logView);
    logGroup->setLayout(logLayBox);
    mainLay->addWidget(logGroup, 1); // растягивается

    // Кнопка для показа/скрытия логов
    toggleLogButton = new QPushButton("Show Event Log");
    mainLay->addWidget(toggleLogButton);

    // Применяем основной layout
    setCentralWidget(central);
    setWindowTitle("Server Control");


    // Сигналы
    connect(browseButton, &QPushButton::clicked, this, &ServerWindow::browseLogDir);
    connect(startButton, &QPushButton::clicked, this, &ServerWindow::startServer);
    connect(stopButton, &QPushButton::clicked, this, &ServerWindow::stopServer);
    connect(toggleLogButton, &QPushButton::clicked, this, &ServerWindow::toggleLogVisibility); // Подключаем сигнал

}

ServerWindow::~ServerWindow()
{
    if (serverThread)
    {
        serverThread->quit();
        serverThread->wait();
    }
}

void ServerWindow::toggleLogVisibility()
{
    bool isVisible = logGroup->isVisible();
    logGroup->setVisible(!isVisible);
    toggleLogButton->setText(isVisible ? "Show Event Log" : "Hide Event Log");
}

void ServerWindow::browseLogDir()
{
    QString dir = QFileDialog::getExistingDirectory(this, "Select Log Directory");
    if (!dir.isEmpty())
        logEdit->setText(dir);
}

void ServerWindow::startServer()
{
    bool ok;
    uint port = portEdit->text().toUInt(&ok);
    if (!ok)
    {
        logView->append("[ERROR] Invalid port number");
        return;
    }
    QString logDir = logEdit->text();
    if (logDir.isEmpty())
    {
        logView->append("[ERROR] Please select log directory");
        return;
    }

    portEdit->setEnabled(false);
    logEdit->setEnabled(false);
    browseButton->setEnabled(false);
    startButton->setEnabled(false);
    stopButton->setEnabled(true);

    server = new communicator(port, logDir.toStdString());
    serverThread = new QThread;
    server->moveToThread(serverThread);

    connect(serverThread, &QThread::started, server, &communicator::work);
    connect(serverThread, &QThread::finished, server, &QObject::deleteLater);
    connect(serverThread, &QThread::finished, serverThread, &QObject::deleteLater);
    connect(server, &communicator::clientConnected, this, &ServerWindow::onClientConnected);
    connect(server, &communicator::clientDisconnected, this, &ServerWindow::onClientDisconnected);
    connect(server, &communicator::messageReceived, this, &ServerWindow::onMessageReceived);
    connect(server, &communicator::messageSent, this, &ServerWindow::onMessageSent);
    connect(server, &communicator::fileListSent, this, &ServerWindow::onFileListSent);
    connect(server, &communicator::fileSent, this, &ServerWindow::onFileSent);
    connect(server, &communicator::clientAuthenticated, this, &ServerWindow::onClientAuthenticated);
    connect(server, &communicator::clientRegistered, this, &ServerWindow::onClientRegistered);
    connect(server, &communicator::logEvent, this, &ServerWindow::onLogEvent);

    serverThread->start();
    logView->append("[INFO] Server thread started");
}

void ServerWindow::stopServer()
{
    if (serverThread)
    {
        server->stop();
        serverThread->quit();
        serverThread->wait();
        server = nullptr;
        serverThread = nullptr;
        logView->append("[INFO] Server stopped");
    }

    portEdit->setEnabled(true);
    logEdit->setEnabled(true);
    browseButton->setEnabled(true);
    startButton->setEnabled(true);
    stopButton->setEnabled(false);
}

void ServerWindow::onClientConnected(QString clientIP, QString clientID)
{
    if (clientBlocks.contains(clientID))
        return;

    auto box = new QGroupBox(clientID + " @ " + clientIP);
    auto form = new QFormLayout;
    box->setLayout(form);

    form->addRow("Status:", new QLabel("Connected"));
    form->addRow("Last msg:", new QLabel(""));
    form->addRow("Files sent:", new QLabel("0"));

    int row = clientCount / 3;
    int col = clientCount % 3;
    clientLayout->addWidget(box, row, col);
    ++clientCount;

    clientBlocks[clientID] = box;
    logView->append("[CONNECT] " + clientID + " (" + clientIP + ")");
}

void ServerWindow::onClientDisconnected(QString clientID)
{
    if (!clientBlocks.contains(clientID))
        return;

    auto box = clientBlocks.take(clientID);
    clientLayout->removeWidget(box);
    delete box;
    --clientCount;
    logView->append("[DISCONNECT] " + clientID);
}

void ServerWindow::onMessageReceived(QString clientID, QString message)
{
    logView->append("[RECV] " + clientID + ": " + message);
    if (clientBlocks.contains(clientID))
    {
        auto form = qobject_cast<QFormLayout *>(clientBlocks[clientID]->layout());
        if (form)
        {
            auto lbl = qobject_cast<QLabel *>(form->itemAt(1, QFormLayout::FieldRole)->widget());
            if (lbl)
                lbl->setText(message);
        }
    }
}

void ServerWindow::onMessageSent(QString clientID, QString header, QString content)
{
    logView->append("[SEND] " + clientID + " [" + header + "]: " + content);
}

void ServerWindow::onFileListSent(QString clientID, int fileCount)
{
    logView->append("[FILES LIST] to " + clientID + ": " + QString::number(fileCount));
}

void ServerWindow::onFileSent(QString clientID, QString filePath)
{
    logView->append("[FILE SENT] " + clientID + " -> " + filePath);
    if (clientBlocks.contains(clientID))
    {
        auto form = qobject_cast<QFormLayout *>(clientBlocks[clientID]->layout());
        if (form)
        {
            auto lbl = qobject_cast<QLabel *>(form->itemAt(2, QFormLayout::FieldRole)->widget());
            if (lbl)
            {
                int cnt = lbl->text().toInt() + 1;
                lbl->setText(QString::number(cnt));
            }
        }
    }
}

void ServerWindow::onClientAuthenticated(QString clientID, bool success)
{
    logView->append(QString("[AUTH] ") + clientID + (success ? " OK" : " FAIL"));
    if (clientBlocks.contains(clientID))
    {
        auto form = qobject_cast<QFormLayout *>(clientBlocks[clientID]->layout());
        if (form)
        {
            auto lbl = qobject_cast<QLabel *>(form->itemAt(0, QFormLayout::FieldRole)->widget());
            if (lbl)
                lbl->setText(success ? "Authenticated" : "Auth Failed");
        }
    }
}

void ServerWindow::onClientRegistered(QString clientID, bool success)
{
    logView->append(QString("[REG] ") + clientID + (success ? " OK" : " FAIL"));
}

void ServerWindow::onLogEvent(QString context, QString message)
{
    QString ts = QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss");
    logView->append("[" + ts + "] " + context + ": " + message);
}
