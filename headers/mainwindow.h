#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QMessageBox>
#include <QFileDialog>
#include <QTreeWidget>
#include <QTableWidget>
#include <QSplitter>
#include <QVBoxLayout>
#include <QHeaderView>

#include <iostream>
#include <fstream>

QT_BEGIN_NAMESPACE
namespace Ui {
class MainWindow;
}
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

    void setupTable(QTableWidget *table);
    void setupTree(QTreeWidget *tree);
    void setupUI();
    void startUI();

private slots:

    void on_action_PEHint_triggered();
    void on_action_Exit_triggered();
    void on_action_Open_triggered();
    void onHeaderClicked(int section);


private:
    Ui::MainWindow *ui;

    QTreeWidget *_tree;
    QTableWidget *_table;
};
#endif // MAINWINDOW_H
