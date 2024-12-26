#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QMessageBox>
#include <QFileDialog>
#include <QTreeWidget>
#include <QTableWidget>
#include <QListWidgetItem>
#include <QSplitter>
#include <QVBoxLayout>
#include <QHeaderView>

#include <iostream>
#include <fstream>
#include <orderedmap.h>

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
    void populateTable(const OrderedMap& orderedMap);
    void baseUI();

private slots:

    void on_action_PEHint_triggered();
    void on_action_Exit_triggered();
    void on_action_Open_triggered();
    void onHeaderClicked(int section);
    void onTreeItemClicked(QTreeWidgetItem *item, int column);
    void onTableItemClicked(QTableWidgetItem *item);

private:
    Ui::MainWindow *ui;

    QTreeWidget *_tree;
    QTableWidget *_table;

    QString _fileName;

    OrderedMap _fileInfo;
    OrderedMap _dosHeader;

};
#endif // MAINWINDOW_H
