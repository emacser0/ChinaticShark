#include "mainwindow.h"
#include <QApplication>
#include <QLocale>
#include <thread>
#include "pcap_thread.hpp"
int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    QLocale cur_locale(QLocale("ko_KR"));
    QLocale::setDefault(cur_locale);
    MainWindow w;
    std::thread pcap_thread(init_pcap_thread,argc,argv);
    w.show();
    return a.exec();
}
