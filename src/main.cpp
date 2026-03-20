#include "mainwindow.h"

#include <QApplication>
#include <QCoreApplication>

int main(int argc, char *argv[])
{
    // Windows defaults to hiding QAction icons in menus; show them for Open / Exit / About, etc.
    QCoreApplication::setAttribute(Qt::AA_DontShowIconsInMenus, false);

    QApplication a(argc, argv);
    MainWindow w;
    w.show();
    return a.exec();
}
