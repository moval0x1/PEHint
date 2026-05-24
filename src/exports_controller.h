#ifndef EXPORTS_CONTROLLER_H
#define EXPORTS_CONTROLLER_H

#include <QObject>

class PEParserNew;
class UIManager;

class ExportsController : public QObject
{
    Q_OBJECT

public:
    explicit ExportsController(UIManager *ui, QObject *parent = nullptr);

    void setParser(PEParserNew *parser);
    void refresh();
    void clear();
    void invalidate();
    void updateLanguageStrings();

private:
    UIManager *m_ui = nullptr;
    PEParserNew *m_parser = nullptr;
    bool m_populated = false;
};

#endif // EXPORTS_CONTROLLER_H
