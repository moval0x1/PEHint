#include "mainwindow.h"
#include "pe_cli_scan.h"

#include <QApplication>
#include <QColor>
#include <QCoreApplication>
#include <QPalette>
#include <QStyleFactory>
#include <QStyleHints>

namespace {

void applyLightTheme(QApplication &app)
{
    // Use Fusion so the UI does not track Windows light/dark mode (the default Windows
    // style follows the system theme and darkens the hex view and chrome).
    app.setStyle(QStyleFactory::create(QStringLiteral("Fusion")));

#if QT_VERSION >= QT_VERSION_CHECK(6, 5, 0)
    app.styleHints()->setColorScheme(Qt::ColorScheme::Light);
#endif

    QPalette pal;
    pal.setColor(QPalette::Window, QColor(240, 240, 240));
    pal.setColor(QPalette::WindowText, Qt::black);
    pal.setColor(QPalette::Base, Qt::white);
    pal.setColor(QPalette::AlternateBase, QColor(245, 245, 245));
    pal.setColor(QPalette::ToolTipBase, QColor(255, 255, 220));
    pal.setColor(QPalette::ToolTipText, Qt::black);
    pal.setColor(QPalette::Text, Qt::black);
    pal.setColor(QPalette::Button, QColor(240, 240, 240));
    pal.setColor(QPalette::ButtonText, Qt::black);
    pal.setColor(QPalette::BrightText, Qt::red);
    pal.setColor(QPalette::Link, QColor(0, 120, 212));
    pal.setColor(QPalette::Highlight, QColor(0, 120, 212));
    pal.setColor(QPalette::HighlightedText, Qt::white);
    pal.setColor(QPalette::PlaceholderText, QColor(120, 120, 120));
    app.setPalette(pal);
}

} // namespace

int main(int argc, char *argv[])
{
    // Windows defaults to hiding QAction icons in menus; show them for Open / Exit / About, etc.
    QCoreApplication::setAttribute(Qt::AA_DontShowIconsInMenus, false);

    if (peCliScanRequested(argc, argv)) {
        return runPeCliScan(argc, argv);
    }

    QApplication a(argc, argv);
    applyLightTheme(a);
    MainWindow w;
    w.show();
    return a.exec();
}
