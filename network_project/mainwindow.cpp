#include <deque>
#include <QTimer>
#include <QStandardItemModel>
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
    ui->packetList->setColumnCount(3);
    QTreeWidgetItem *header = new QTreeWidgetItem;
    header->setText(0, "No.");
    header->setText(1, "Source");
    header->setText(2, "Destination");
    header->setText(3, "Protocol");
    header->setText(4, "Length");
    ui->packetList->setHeaderItem(header);
    refresh_timer=new QTimer;
    connect(refresh_timer,SIGNAL(timeout()),this,SLOT(on_timer()));
    refresh_timer->start(300);
    packet_list_index=1;
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
        QTreeWidgetItem *item = new QTreeWidgetItem;
        item->setText(0, QString::number(packet_list_index++));
        item->setText(1, result_ph.header_info.source.c_str());
        item->setText(2, result_ph.header_info.destination.c_str());
        item->setText(3, result_ph.header_info.protocol.c_str());
        item->setText(4, QString::number(result_ph.header_info.cap_len));
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
        for(auto i : cur_ph->http) {
            item->appendRow(new QStandardItem(QString::fromUtf8(i.c_str())));
        }
    }
    if(cur_ph->flags & DNS_FLAG) {
        auto *item = new QStandardItem("Domain Name System");
        model->appendRow(item);
        item->appendRow(new QStandardItem(cur_ph->dns.c_str()));
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
