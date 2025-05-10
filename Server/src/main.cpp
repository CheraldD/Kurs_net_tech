#include <QApplication>
#include "serverwindow.h"
#include "base.h"
#include "protocol.h"
#include "data_handler.h"

int main(int argc, char* argv[])
{
    QApplication app(argc, argv);
    ServerWindow w;
    w.show();
    return app.exec();
}
