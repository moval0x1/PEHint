#include "pe_compare_dialog.h"
#include "pe_compare.h"
#include "pe_data_model.h"
#include "pe_parser_new.h"
#include "pe_analysis.h"
#include "language_manager.h"

#include <QApplication>
#include <QClipboard>
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
    , m_localBasePath(baseFilePath)
{
    setWindowTitle(LANG("UI/compare_window_title"));
    setMinimumSize(700, 500);
    resize(900, 640);

    auto *root = new QVBoxLayout(this);
    root->setContentsMargins(8, 8, 8, 8);
    root->setSpacing(6);

    // Base file row
    m_baseLabel = new QLabel(this);
    m_baseLabel->setTextFormat(Qt::RichText);
    updateBaseLabel();
    root->addWidget(m_baseLabel);

    // Second file row
    auto *rowB = new QHBoxLayout;
    rowB->setSpacing(4);
    auto *labelB = new QLabel(LANG("UI/compare_label_b"), this);
    labelB->setTextFormat(Qt::RichText);
    rowB->addWidget(labelB);
    m_secondPathEdit = new QLineEdit(this);
    m_secondPathEdit->setPlaceholderText(LANG("UI/compare_placeholder"));
    rowB->addWidget(m_secondPathEdit, 1);
    m_browseButton = new QPushButton(LANG("UI/compare_browse"), this);
    rowB->addWidget(m_browseButton);
    root->addLayout(rowB);

    // Action row: Compare | Swap | Copy
    auto *rowActions = new QHBoxLayout;
    rowActions->setSpacing(6);
    m_compareButton = new QPushButton(LANG("UI/compare_button"), this);
    m_compareButton->setDefault(true);
    rowActions->addWidget(m_compareButton, 1);
    m_swapButton = new QPushButton(LANG("UI/compare_swap"), this);
    m_swapButton->setToolTip(LANG("UI/compare_swap_tooltip"));
    rowActions->addWidget(m_swapButton);
    m_copyButton = new QPushButton(LANG("UI/compare_copy"), this);
    m_copyButton->setToolTip(LANG("UI/compare_copy_tooltip"));
    m_copyButton->setEnabled(false);
    rowActions->addWidget(m_copyButton);
    root->addLayout(rowActions);

    // Result view
    m_resultView = new QTextBrowser(this);
    m_resultView->setOpenExternalLinks(false);
    root->addWidget(m_resultView, 1);

    connect(m_browseButton,  &QPushButton::clicked, this, &PECompareDialog::browseSecondFile);
    connect(m_compareButton, &QPushButton::clicked, this, &PECompareDialog::runCompare);
    connect(m_swapButton,    &QPushButton::clicked, this, &PECompareDialog::swapFiles);
    connect(m_copyButton,    &QPushButton::clicked, this, &PECompareDialog::copyResult);
    connect(m_secondPathEdit, &QLineEdit::returnPressed, this, &PECompareDialog::runCompare);
}

void PECompareDialog::updateBaseLabel()
{
    const QString name = QFileInfo(m_localBasePath).fileName();
    const QString display = name.isEmpty() ? LANG("UI/compare_none") : name;
    m_baseLabel->setText(LANG_PARAM("UI/compare_label_a", "name", display.toHtmlEscaped()));
    m_baseLabel->setToolTip(m_localBasePath);
}

void PECompareDialog::browseSecondFile()
{
    const QString startDir = QFileInfo(m_localBasePath).absolutePath();
    const QString filter = QString("%1;;%2")
        .arg(LANG("UI/file_filter_pe"), LANG("UI/file_filter_all"));
    const QString path = QFileDialog::getOpenFileName(
        this,
        LANG("UI/compare_select_title"),
        startDir,
        filter);
    if (!path.isEmpty()) {
        m_secondPathEdit->setText(QDir::toNativeSeparators(path));
    }
}

void PECompareDialog::swapFiles()
{
    const QString second = m_secondPathEdit->text().trimmed();
    if (second.isEmpty()) {
        QMessageBox::information(this,
                                 LANG("UI/compare_swap_msgbox_title"),
                                 LANG("UI/compare_swap_no_file"));
        return;
    }
    m_secondPathEdit->setText(QDir::toNativeSeparators(m_localBasePath));
    m_localBasePath = second;
    updateBaseLabel();
    runCompare();
}

void PECompareDialog::copyResult()
{
    const QString text = m_resultView->toPlainText();
    if (!text.isEmpty())
        QApplication::clipboard()->setText(text);
}

void PECompareDialog::runCompare()
{
    const QString secondPath = m_secondPathEdit->text().trimmed();
    if (secondPath.isEmpty()) {
        QMessageBox::warning(this,
                             LANG("UI/compare_window_title"),
                             LANG("UI/compare_select_msg"));
        return;
    }
    if (!QFileInfo::exists(secondPath)) {
        QMessageBox::warning(this,
                             LANG("UI/compare_window_title"),
                             LANG_PARAM("UI/compare_file_not_found", "path", secondPath));
        return;
    }

    m_resultView->setHtml(QStringLiteral("<p>%1</p>").arg(LANG("UI/compare_parsing").toHtmlEscaped()));
    m_compareButton->setEnabled(false);
    m_swapButton->setEnabled(false);
    m_copyButton->setEnabled(false);
    QCoreApplication::processEvents();

    // Parse second file
    PEParserNew parserB;
    if (!parserB.loadFile(secondPath)) {
        m_resultView->setHtml(
            QStringLiteral("<p style='color:red'>%1</p>")
                .arg(LANG("UI/compare_parse_failed").toHtmlEscaped()));
        m_compareButton->setEnabled(true);
        m_swapButton->setEnabled(true);
        return;
    }
    QByteArray fileDataB;
    {
        QFile f(secondPath);
        if (f.open(QIODevice::ReadOnly))
            fileDataB = f.readAll();
    }
    PEDataModel modelB = parserB.getDataModel();
    if (!fileDataB.isEmpty())
        PEAnalysis::analyzeIntoModel(fileDataB, modelB, secondPath);

    PECompare::Result result;

    if (m_localBasePath == m_baseFilePath) {
        result = PECompare::compare(m_baseModel, modelB, m_localBasePath, secondPath);
    } else {
        PEParserNew parserA;
        if (!parserA.loadFile(m_localBasePath)) {
            m_resultView->setHtml(
                QStringLiteral("<p style='color:red'>%1</p>")
                    .arg(LANG_PARAM("UI/compare_base_parse_failed", "path",
                                    m_localBasePath).toHtmlEscaped()));
            m_compareButton->setEnabled(true);
            m_swapButton->setEnabled(true);
            return;
        }
        QByteArray fileDataA;
        {
            QFile f(m_localBasePath);
            if (f.open(QIODevice::ReadOnly))
                fileDataA = f.readAll();
        }
        PEDataModel modelA = parserA.getDataModel();
        if (!fileDataA.isEmpty())
            PEAnalysis::analyzeIntoModel(fileDataA, modelA, m_localBasePath);

        result = PECompare::compare(modelA, modelB, m_localBasePath, secondPath);
    }

    m_resultView->setHtml(PECompare::toHtml(result));
    m_compareButton->setEnabled(true);
    m_swapButton->setEnabled(true);
    m_copyButton->setEnabled(true);
}
