#include <deque>
#include <QTimer>
#include <QStandardItemModel>
#include <QFileDialog>
#include <QFile>
#include <QTextStream>
#include <thread>
#include <pthread.h>
#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "pcap_thread.hpp"
extern bool stop;
extern std::deque<ProcessedHeader> result_header;
MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    auto *header = new QTreeWidgetItem;
    header->setText(0, "No.");
    header->setText(1, "Source");
    header->setText(2, "Destination");
    header->setText(3, "Protocol");
    header->setText(4, "Length");
    header->setText(5, "Info");
    ui->packetList->setHeaderItem(header);
    refresh_timer=new QTimer;
    connect(refresh_timer,SIGNAL(timeout()),this,SLOT(on_timer()));
    refresh_timer->start(300);
    auto *thread_header = new QTreeWidgetItem;
    thread_header->setText(0,"device name");
    thread_header->setText(1,"Filter");
    ui->threadList->setHeaderItem(thread_header);
    ui->devEdit->clear();
    ui->filterEdit->clear();
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::
on_timer() {
    while(result_header.size()) {
        auto &result_ph=result_header.back();
        ph_list.push_back(result_ph);
        auto *item = new QTreeWidgetItem;
        item->setText(0, QString::number(ph_list.size()));
        item->setText(1, result_ph.header_info.source.c_str());
        item->setText(2, result_ph.header_info.destination.c_str());
        item->setText(3, result_ph.header_info.protocol.c_str());
        item->setText(4, QString::number(result_ph.header_info.cap_len));
        item->setText(5, result_ph.header_info.info.c_str());
        ui->packetList->addTopLevelItem(item);
        result_header.pop_back();
    }
    refresh_timer->start(300);
}

void MainWindow::on_packetList_itemSelectionChanged()
{
    auto index = ui->packetList->currentIndex();
    auto cur_ph = ph_list.begin()+index.row();
    auto *model = new QStandardItemModel;
    if(cur_ph->flags & ETHER_FLAG) {
        auto *item = new QStandardItem(cur_ph->ether_info.c_str());
        model->appendRow(item);
        item->appendRow(new QStandardItem(cur_ph->ether.c_str()));
    }
    if(cur_ph->flags & IP_FLAG) {
        auto *item = new QStandardItem(cur_ph->ip_info.c_str());
        model->appendRow(item);
        item->appendRow(new QStandardItem(cur_ph->ip.c_str()));
    }
    if(cur_ph->flags & ARP_FLAG) {
        auto *item = new QStandardItem("Address Resolution Protocol");
        model->appendRow(item);
        item->appendRow(new QStandardItem(cur_ph->arp.c_str()));
    }
    if(cur_ph->flags & TCP_FLAG) {
        auto *item = new QStandardItem(cur_ph->tcp_info.c_str());
        model->appendRow(item);
        item->appendRow(new QStandardItem(cur_ph->tcp.c_str()));
    }
    if(cur_ph->flags & UDP_FLAG) {
        auto *item = new QStandardItem(cur_ph->udp_info.c_str());
        model->appendRow(item);
        item->appendRow(new QStandardItem(cur_ph->udp.c_str()));
    }
    if(cur_ph->flags & HTTP_FLAG) {
        auto *item = new QStandardItem("Hypertext Transfer Protocol");
        model->appendRow(item);
        for(auto &i : cur_ph->http) {
            item->appendRow(new QStandardItem(QString::fromUtf8(i.c_str())));
        }
    }
    if(cur_ph->flags & DNS_FLAG) {
        auto *item = new QStandardItem("Domain Name System");
        model->appendRow(item);
        for(std::string &i : cur_ph->dns) {
            item->appendRow(new QStandardItem(i.c_str()));
        }
    }
    if(cur_ph->flags & SMTP_FLAG) {
        auto *item = new QStandardItem("Simple Mail Transfer Protocol");
        model->appendRow(item);
        for(auto &i : cur_ph->smtp) {
            item->appendRow(new QStandardItem(QString::fromUtf8(i.c_str())));
        }
    }
    ui->hexView->setText(cur_ph->hex.c_str());
    ui->headerView->setModel(model);
}

void MainWindow::on_startButton_clicked()
{
    stop = 0;
}

void MainWindow::on_stopButton_clicked()
{
    stop = 1;
}

void MainWindow::on_addButton_clicked()
{
    std::string dev_name = ui->devEdit->text().toStdString();
    std::string filter = ui->filterEdit->text().toStdString();
    ui->devEdit->clear();
    ui->filterEdit->clear();
    auto *new_pcap_thread = new std::thread(
                init_pcap_thread,
                dev_name,filter);
    thread_list.push_back(new_pcap_thread);
    auto *item = new QTreeWidgetItem();
    item->setText(0,dev_name.c_str());
    item->setText(1,filter.c_str());
    ui->threadList->addTopLevelItem(item);
}

void MainWindow::on_ClearButton_clicked()
{
    for(auto &i : thread_list) {
        auto handle = i->native_handle();
        i->detach();
        pthread_cancel(handle);
    }
    thread_list.clear();
    ui->threadList->clear();
}

void MainWindow::on_deleteButton_clicked()
{
    int index = ui->threadList->currentIndex().row();
    if(index>=0 && index<thread_list.size()) {
        auto handle = thread_list[index]->native_handle();
        thread_list[index]->detach();
        pthread_cancel(handle);
        thread_list.erase(thread_list.begin()+index);
        ui->threadList->takeTopLevelItem(index);
    }
}

void MainWindow::on_saveButton_clicked()
{
    QFileDialog dialog;
    dialog.setFileMode(QFileDialog::AnyFile);
    QString file_name = dialog.getSaveFileName();
    QFile file(file_name);
    if(!file.open(QIODevice::WriteOnly)) {
        return;
    }
    QTextStream stream(&file);
    for(uint32_t i=0;i<ph_list.size();i++) {
        stream << "---------------------------\n";
        auto *cur_ph = &(ph_list[i]);
        stream << i << " "
               << cur_ph->header_info.source.c_str() << " "
               << cur_ph->header_info.destination.c_str() << " "
               << cur_ph->header_info.protocol.c_str() << " "
               << cur_ph->header_info.cap_len << " "
               << cur_ph->header_info.info.c_str() << "\n";
        if(cur_ph->flags & ETHER_FLAG) {
            stream << cur_ph->ether_info.c_str()
                   << "\n"
                   << cur_ph->ether.c_str();
        }
        if(cur_ph->flags & IP_FLAG) {
            stream << cur_ph->ip_info.c_str()
                   << "\n"
                   << cur_ph->ip.c_str();
        }
        if(cur_ph->flags & ARP_FLAG) {
            stream << "Address Resolution Protocol\n"
                   << cur_ph->arp.c_str()
                   << "\n";
        }
        if(cur_ph->flags & TCP_FLAG) {
            stream << cur_ph->tcp_info.c_str()
                   << "\n"
                   << cur_ph->tcp.c_str()
                   << "\n";
        }
        if(cur_ph->flags & UDP_FLAG) {
            stream << cur_ph->udp_info.c_str()
                   << "\n"
                   << cur_ph->udp.c_str()
                   << "\n";
        }
        if(cur_ph->flags & HTTP_FLAG) {
            stream << "Hypertext Transfer Protocol\n";
            for(auto &i : cur_ph->http) {
                stream << QString::fromUtf8(i.c_str())
                       << "\n";
            }
        }
        if(cur_ph->flags & DNS_FLAG) {
            stream << "Domain Name System\n";
            for(auto &i : cur_ph->dns) {
                stream << i.c_str()
                       << "\n";
            }
        }
        if(cur_ph->flags & SMTP_FLAG) {
            stream << "Simple Mail Transfer Protocol\n";
            for(auto &i : cur_ph->smtp) {
                stream << QString::fromUtf8(i.c_str())
                       << "\n";
            }
        }
        if(cur_ph->flags & BITTORRENT_FLAG) {

        }
    }
    file.close();
}

void MainWindow::on_packetClearButton_clicked()
{
    ph_list.clear();
    ui->packetList->clear();
}
