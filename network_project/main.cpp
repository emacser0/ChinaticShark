#include "mainwindow.h"
#include <QApplication>
#include <QLocale>
#include <thread>
#include "pcap_thread.hpp"
int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    MainWindow w;
    w.show();
    return a.exec();
}
