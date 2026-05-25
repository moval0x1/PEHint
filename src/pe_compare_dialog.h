#ifndef PE_COMPARE_DIALOG_H
#define PE_COMPARE_DIALOG_H

#include <QDialog>

class PEDataModel;
class QTextBrowser;
class QLabel;
class QPushButton;
class QLineEdit;

class PECompareDialog : public QDialog
{
    Q_OBJECT

public:
    explicit PECompareDialog(const PEDataModel &baseModel,
                             const QString &baseFilePath,
                             QWidget *parent = nullptr);

private slots:
    void browseSecondFile();
    void runCompare();

private:
    const PEDataModel &m_baseModel;
    QString m_baseFilePath;

    QLabel *m_baseLabel = nullptr;
    QLineEdit *m_secondPathEdit = nullptr;
    QPushButton *m_browseButton = nullptr;
    QPushButton *m_compareButton = nullptr;
    QTextBrowser *m_resultView = nullptr;
};

#endif // PE_COMPARE_DIALOG_H
