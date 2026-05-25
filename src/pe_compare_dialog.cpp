#include "pe_compare_dialog.h"
#include "pe_compare.h"
#include "pe_data_model.h"
#include "pe_parser_new.h"
#include "pe_analysis.h"
#include "language_manager.h"

#include <QDir>
#include <QFileDialog>
#include <QFileInfo>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QTextBrowser>
#include <QVBoxLayout>

PECompareDialog::PECompareDialog(const PEDataModel &baseModel,
                                 const QString &baseFilePath,
                                 QWidget *parent)
    : QDialog(parent)
    , m_baseModel(baseModel)
    , m_baseFilePath(baseFilePath)
{
    setWindowTitle(QStringLiteral("PE Compare"));
    setMinimumSize(700, 500);
    resize(860, 600);

    auto *root = new QVBoxLayout(this);
    root->setContentsMargins(8, 8, 8, 8);
    root->setSpacing(6);

    // Base file row
    const QString baseName = QFileInfo(baseFilePath).fileName();
    m_baseLabel = new QLabel(
        QStringLiteral("<b>Base file (A):</b> %1").arg(baseName.isEmpty()
            ? QStringLiteral("(none)") : baseName), this);
    root->addWidget(m_baseLabel);

    // Second file row
    auto *rowB = new QHBoxLayout;
    rowB->setSpacing(4);
    auto *labelB = new QLabel(QStringLiteral("<b>Compare with (B):</b>"), this);
    rowB->addWidget(labelB);
    m_secondPathEdit = new QLineEdit(this);
    m_secondPathEdit->setPlaceholderText(QStringLiteral("Select a PE file…"));
    rowB->addWidget(m_secondPathEdit, 1);
    m_browseButton = new QPushButton(QStringLiteral("Browse…"), this);
    rowB->addWidget(m_browseButton);
    root->addLayout(rowB);

    // Compare button
    m_compareButton = new QPushButton(QStringLiteral("Compare"), this);
    m_compareButton->setDefault(true);
    root->addWidget(m_compareButton);

    // Result view
    m_resultView = new QTextBrowser(this);
    m_resultView->setOpenExternalLinks(false);
    root->addWidget(m_resultView, 1);

    connect(m_browseButton, &QPushButton::clicked, this, &PECompareDialog::browseSecondFile);
    connect(m_compareButton, &QPushButton::clicked, this, &PECompareDialog::runCompare);
    connect(m_secondPathEdit, &QLineEdit::returnPressed, this, &PECompareDialog::runCompare);
}

void PECompareDialog::browseSecondFile()
{
    const QString path = QFileDialog::getOpenFileName(
        this,
        QStringLiteral("Select PE file to compare"),
        QFileInfo(m_baseFilePath).absolutePath(),
        QStringLiteral("PE Files (*.exe *.dll *.sys *.scr *.drv *.bin);;All Files (*)"));
    if (!path.isEmpty()) {
        m_secondPathEdit->setText(QDir::toNativeSeparators(path));
    }
}

void PECompareDialog::runCompare()
{
    const QString secondPath = m_secondPathEdit->text().trimmed();
    if (secondPath.isEmpty()) {
        QMessageBox::warning(this, QStringLiteral("PE Compare"),
                             QStringLiteral("Please select a second PE file."));
        return;
    }
    if (!QFileInfo::exists(secondPath)) {
        QMessageBox::warning(this, QStringLiteral("PE Compare"),
                             QStringLiteral("File not found:\n%1").arg(secondPath));
        return;
    }

    m_resultView->setHtml(QStringLiteral("<p>Parsing…</p>"));
    m_compareButton->setEnabled(false);
    QCoreApplication::processEvents();

    PEParserNew parser;
    if (!parser.loadFile(secondPath)) {
        m_resultView->setHtml(QStringLiteral("<p style='color:red'>Failed to parse the selected PE file.</p>"));
        m_compareButton->setEnabled(true);
        return;
    }

    // Run extra analysis so findings and metrics are populated
    QByteArray fileData;
    {
        QFile f(secondPath);
        if (f.open(QIODevice::ReadOnly)) {
            fileData = f.readAll();
        }
    }
    PEDataModel secondModel = parser.getDataModel();
    if (!fileData.isEmpty()) {
        PEAnalysis::analyzeIntoModel(fileData, secondModel, secondPath);
    }

    const PECompare::Result result = PECompare::compare(
        m_baseModel, secondModel, m_baseFilePath, secondPath);

    m_resultView->setHtml(PECompare::toHtml(result));
    m_compareButton->setEnabled(true);
}
