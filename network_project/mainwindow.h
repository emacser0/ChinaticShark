#ifndef MAINWINDOW_H
#define MAINWINDOW_H
#include <thread>
#include <QMainWindow>
#include <QModelIndex>
#include <QTimer>
#include <QVector>
#include "pcap_thread.hpp"
namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

protected:
    QTimer *refresh_timer;
    QVector<ProcessedHeader> ph_list;
    QVector<std::thread*> thread_list;
    uint32_t packet_list_index;
signals:
    void timeout();
private slots:
    void on_timer();
    void on_packetList_itemSelectionChanged();

    void on_startButton_clicked();

    void on_stopButton_clicked();

    void on_addButton_clicked();

    void on_ClearButton_clicked();

    void on_deleteButton_clicked();

private:
    Ui::MainWindow *ui;
};

#endif // MAINWINDOW_H
