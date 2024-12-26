#include "mainwindow.h"
#include "ui_mainwindow.h"

#include "PEFILE.h"

QMap<QString, QString> mapInfo;
QString fileName;

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
    fileName = peFile.fileName().split('/').last();

    if (arc == 1) {
        exit(1);
    }

    else if (arc == 32) {
        PE32FILE pe32(&peFile);
        pe32.PrintInfo();

        mapInfo = pe32.PrintFileInfo();
        MainWindow::setupUI();

        populateTable(mapInfo);

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

    if (section == 0) {
        populateTable(mapInfo);
    }else if (section == 1) {
        populateTable(mapInfo);
    }
}

void MainWindow::setupUI() {

    baseUI();

    // Setup tree and table contents
    setupTree(_tree);
    setupTable(_table);

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

    // Optional: Set initial sizes for splitter widgets
    splitter->setStretchFactor(0, 1); // Tree gets more focus
    splitter->setStretchFactor(1, 2); // Table takes up more space

    QVBoxLayout *layout = new QVBoxLayout(centralWidget);
    layout->addWidget(splitter);
    centralWidget->setLayout(layout);
}

void MainWindow::startUI()
{
    baseUI();

    // Configure the tree widget
    _tree->setHeaderLabel("");
    _tree->clear();
}

void MainWindow::populateTable(const QMap<QString, QString> &mapInfo)
{
    // Set the row count to match the number of entries in the map
    _table->setRowCount(mapInfo.size());

    // Iterate through the map and populate the table
    int row = 0;
    for (auto it = mapInfo.begin(); it != mapInfo.end(); ++it, ++row) {
        // Set key in the first column
        _table->setItem(row, 0, new QTableWidgetItem(it.key()));

        // Set value in the second column
        _table->setItem(row, 1, new QTableWidgetItem(it.value()));
    }
}

void MainWindow::setupTree(QTreeWidget *tree) {

    tree->header()->setSectionsClickable(true);
    tree->setHeaderLabel(fileName);

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

    // Optional: Set the row height dynamically to fit content
    table->verticalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);

    // Optional: Allow horizontal header resizing by the user if needed
    table->horizontalHeader()->setStretchLastSection(false); // Disable stretching

    // Connect header signal to onHeaderClicked
    connect(table->horizontalHeader(), &QHeaderView::sectionClicked, this, &MainWindow::onHeaderClicked);
}
