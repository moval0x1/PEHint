#include "mainwindow.h"
#include "./ui_mainwindow.h"
#include <QMessageBox>

#include <iostream>
#include <fstream>
#include "PEFILE.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    this->setFixedSize(1337, 741);

    // Set icon
    QIcon icon;
    icon.addFile(":/images/imgs/PEHint-ico.ico");
    this->setWindowIcon(icon);

    // Prepare arguments for Main function
    char path[] = "C:\\Users\\DEV\\Desktop\\Codes\\buffer.exe";
    char* argv[] = { path }; // Argument array
    int a = MainWindow::Main(2, argv);   // Call Main function
}

int MainWindow::Main(int argc, char* argv[])
{
    if (argc != 2) {
        printf("Usage: %s [path to executable]\n", argv[0]);
        return 1;
    }

    FILE * PpeFile;
    ::fopen_s(&PpeFile, argv[0], "rb");

    if (PpeFile == NULL) {
        printf("Can't open file.\n");
        return 1;
    }

    if (INITPARSE(PpeFile) == 1) {
        exit(1);
    }
    else if (INITPARSE(PpeFile) == 32) {
        PE32FILE PeFile_1(argv[0], PpeFile);
        PeFile_1.PrintInfo();
        ::fclose(PpeFile);
        ::exit(0);
    }
    else if (INITPARSE(PpeFile) == 64) {
        PE64FILE PeFile_1(argv[0], PpeFile);
        PeFile_1.PrintInfo();
        ::fclose(PpeFile);
        ::exit(0);
    }

    return 0;
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

