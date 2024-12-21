#include "mainwindow.h"
#include "ui_mainwindow.h"

#include "PEFILE.h"

#include <QSplitter>
#include <QTreeWidget>
#include <QTableWidget>
#include <QVBoxLayout>
#include <QHeaderView>


MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent), _tree(new QTreeWidget(this)), _table(new QTableWidget(this))
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    this->setFixedSize(1337, 741);

    // Set icon
    QIcon icon;
    icon.addFile(":/images/imgs/PEHint-ico.ico");
    this->setWindowIcon(icon);

    MainWindow::setupUI();

    connect(_tree, &QTreeWidget::itemClicked, this, &MainWindow::onTreeItemClicked);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_action_PEHint_triggered()
{
    QPixmap pehintIcon(":/images/imgs/PEHint-ico.ico");

    QString msg = "<b>PEHint - Portable Executable Hint</b>";
    msg += "<br/>";
    msg += "Author  : <a href='https://moval0x1.github.io/'>moval0x1</a><br/>";
    msg += "<br/>";
    msg += "\nThis software that was created for study purposes.<br/>Feel free to use it and help improve. ;)";
    msg += "<br/>";


    QMessageBox msgBox(this);
    msgBox.setProperty("hasUrl", true);

    msgBox.setWindowTitle(tr("About PEHint"));
    msgBox.setTextFormat(Qt::RichText);

    msgBox.setText(msg);
    msgBox.setAutoFillBackground(true);
    msgBox.setIconPixmap(pehintIcon);

    msgBox.setStandardButtons(QMessageBox::Ok);
    msgBox.exec();
}

void MainWindow::on_action_Exit_triggered()
{
    QApplication::quit();
}

void MainWindow::on_action_Open_triggered()
{
    // Open a file dialog to select a DLL or EXE file
    QString filePath = QFileDialog::getOpenFileName(this, tr("Open File"), QString(), tr("Executable Files (*.exe *.dll);;All Files (*.*)"));

    if (filePath.isEmpty()) {
        return; // If no file is selected, do nothing
    }

    // Open the file using C-style file handling
    FILE *PpeFile = ::fopen(filePath.toStdString().c_str(), "rb"); // Open in binary mode

    if (!PpeFile) {
        QMessageBox::critical(this, tr("Error"), tr("Failed to open the file."));
        return;
    }

    // Do something with the file (e.g., read or process it)
    QMessageBox::information(this, tr("File Opened"), tr("Successfully opened the file: %1").arg(filePath));

    if (INITPARSE(PpeFile) == 1) {
        exit(1);
    }
    else if (INITPARSE(PpeFile) == 32) {
        PE32FILE PeFile_1(filePath.toStdString().c_str(), PpeFile);
        PeFile_1.PrintInfo();
        ::fclose(PpeFile);
        ::exit(0);
    }
    else if (INITPARSE(PpeFile) == 64) {
        PE64FILE PeFile_1(filePath.toStdString().c_str(), PpeFile);
        PeFile_1.PrintInfo();
        ::fclose(PpeFile);
        ::exit(0);
    }

    // Close the file when done
    fclose(PpeFile);
}

void MainWindow::onTreeItemClicked(QTreeWidgetItem *item, int column) {
    // Clear the table before updating
    _table->clearContents();

    if (item->text(0) == "DOS HEADER") {
        _table->setRowCount(2);
        _table->setItem(0, 0, new QTableWidgetItem("Property"));
        _table->setItem(0, 1, new QTableWidgetItem("DOS Header Details"));
    } else if (item->text(0) == "RICH HEADER") {
        _table->setRowCount(2);
        _table->setItem(0, 0, new QTableWidgetItem("Entropy"));
        _table->setItem(0, 1, new QTableWidgetItem("7.609"));
    }
}

void MainWindow::onHeaderClicked(int section) {

    _table->clearContents();
    _table->setHorizontalHeaderLabels({"Property", "Value"});  // Restore headers

    if (section == 0) {
        _table->setRowCount(2);
        _table->setItem(0, 0, new QTableWidgetItem("Header"));
        _table->setItem(0, 1, new QTableWidgetItem("Property Column Clicked"));
    } else if (section == 1) {
        _table->setRowCount(2);
        _table->setItem(0, 0, new QTableWidgetItem("Header"));
        _table->setItem(0, 1, new QTableWidgetItem("Value Column Clicked"));
    }
}

void MainWindow::setupUI() {
    // Use class members instead of creating new local variables
    QSplitter *splitter = new QSplitter(this);
    splitter->addWidget(_tree);
    splitter->addWidget(_table);

    // Setup tree and table
    setupTree(_tree);
    setupTable(_table);

    // Set the splitter as the central widget
    setCentralWidget(splitter);
}

void MainWindow::setupTree(QTreeWidget *tree) {

    tree->header()->setSectionsClickable(true);
    tree->setHeaderLabel("FileName.exe");

    // Connect header sectionClicked signal
    connect(tree->header(), &QHeaderView::sectionClicked, this, &MainWindow::onHeaderClicked);

    // Add items to the tree
    QTreeWidgetItem *fileItem = new QTreeWidgetItem(tree);
    fileItem->setText(0, "DOS HEADER");

    QTreeWidgetItem *dosHeader = new QTreeWidgetItem(tree);
    dosHeader->setText(0, "RICH HEADER");

    QTreeWidgetItem *richHeader = new QTreeWidgetItem(tree);
    richHeader->setText(0, "NT HEADERS");

    // Add sub-items
    QTreeWidgetItem *ntHeader = new QTreeWidgetItem(tree);
    ntHeader->setText(0, "SECTION HEADERS");

    tree->expandAll();  // Optional: expand all nodes

}


void MainWindow::setupTable(QTableWidget *table) {

    // Set up the table with headers
    table->setColumnCount(2);
    table->setHorizontalHeaderLabels({"Property", "Value"});

    // Connect header signal to onHeaderClicked
    connect(table->horizontalHeader(), &QHeaderView::sectionClicked, this, &MainWindow::onHeaderClicked);
}
