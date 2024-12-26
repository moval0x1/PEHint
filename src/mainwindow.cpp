#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "PEFILE.h"

const QString peHintVersion = "v0.1";

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

    startUI();

    connect(_tree, &QTreeWidget::itemClicked, this, &MainWindow::onTreeItemClicked);

    this->setWindowTitle(QString("PEHint %1").arg(peHintVersion));

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

    // Open the file using QFile
    QFile peFile(filePath);

    if (!peFile.open(QIODevice::ReadOnly)) {
        QMessageBox::critical(this, tr("Error"), tr("Failed to open the file."));
        return;
    }

    int arc = INITPARSE(peFile);

    // Get only the fileName from the binary
    _fileName = peFile.fileName().split('/').last();
    this->setWindowTitle(QString("PEHint %1 - %2").arg(peHintVersion).arg(peFile.fileName()));

    if (arc == 1) {
        exit(1);
    }

    else if (arc == 32) {
        PE32FILE pe32(&peFile);
        pe32.PrintInfo();

        _fileInfo = pe32.PrintFileInfo();
        _dosHeader = pe32.PrintDOSHeaderInfo();

        MainWindow::setupUI();
        MainWindow::populateTable(_fileInfo);

    }
    else if (arc == 64) {
        //PE64FILE pe64(filePath.toStdString().c_str(), peFile);
        //pe64.PrintInfo();
    }

    // Close the file when done
    peFile.close();
}

void MainWindow::onHeaderClicked(int section) {

    _table->clearContents();
    _table->setHorizontalHeaderLabels({"Property", "Value"});  // Restore headers

    // if (section == 0) {
    //     MainWindow::populateTable(_fileInfo);
    // }else if (section == 1) {
    //     MainWindow::populateTable(_fileInfo);
    // }
    MainWindow::populateTable(_fileInfo);
}

void MainWindow::onTreeItemClicked(QTreeWidgetItem *item, int column) {
    // Clear the table before updating
    _table->clearContents();
    if (item->text(0) == "DOS HEADER") {
        MainWindow::populateTable(_dosHeader);
    } else if (item->text(0) == "RICH HEADER") {
        _table->setRowCount(2);
        _table->setItem(0, 0, new QTableWidgetItem("Entropy"));
        _table->setItem(0, 1, new QTableWidgetItem("7.609"));
    }
}

void MainWindow::onTableItemClicked(QTableWidgetItem *item) {
    if (item) {
        QString text = item->text();
        qInfo() << "Clicked item text:" << text;
    }
}

void MainWindow::setupUI() {

    MainWindow::baseUI();

    // Setup tree and table contents
    MainWindow::setupTree(_tree);
    MainWindow::setupTable(_table);

    // Set the splitter as the central widget of the main window
    //setCentralWidget(splitter);
}

void MainWindow::baseUI()
{
    // Create a central widget if none exists
    QWidget *centralWidget = new QWidget(this);
    this->setCentralWidget(centralWidget);

    // Use a layout to manage the _tree and _table widgets
    QSplitter *splitter = new QSplitter(Qt::Horizontal, centralWidget);
    splitter->addWidget(_tree);
    splitter->addWidget(_table);

    // Set initial sizes for splitter widgets
    splitter->setStretchFactor(0, 1); // Tree gets more focus
    splitter->setStretchFactor(1, 2); // Table takes up more space

    QVBoxLayout *layout = new QVBoxLayout(centralWidget);
    layout->addWidget(splitter);
    centralWidget->setLayout(layout);
}

void MainWindow::startUI()
{
    MainWindow::baseUI();

    // Configure the tree widget
    _tree->setHeaderLabel("");
    _tree->clear();
}

void MainWindow::populateTable(const OrderedMap& orderedMap)
{
    const auto& keys = orderedMap.orderedKeys();

    _table->setRowCount(keys.size());

    int row = 0;
    for (const QString& key : keys) {
        _table->setItem(row, 0, new QTableWidgetItem(key));
        _table->setItem(row, 1, new QTableWidgetItem(orderedMap.value(key)));
        ++row;
    }
}

void MainWindow::setupTree(QTreeWidget *tree) {

    tree->header()->setSectionsClickable(true);
    tree->setHeaderLabel(_fileName);

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

    tree->expandAll();  // expand all nodes

    // Connect header sectionClicked signal
    connect(tree->header(), &QHeaderView::sectionClicked, this, &MainWindow::onHeaderClicked);
}

void MainWindow::setupTable(QTableWidget *table) {

    // Set up the table with headers
    table->setColumnCount(2);
    table->setHorizontalHeaderLabels({"Property", "Value"});

    // Automatically adjust the "Property" and "Value" column widths to fit content
    table->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    table->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);

    // Set the row height dynamically to fit content
    table->verticalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);

    // Allow horizontal header resizing by the user if needed
    table->horizontalHeader()->setStretchLastSection(false); // Disable stretching

    // Connect the itemClicked signal to the onTableItemClicked slot
    connect(_table, &QTableWidget::itemClicked, this, &MainWindow::onTableItemClicked);
}
