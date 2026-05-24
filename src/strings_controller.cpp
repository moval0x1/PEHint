#include "strings_controller.h"

#include "pe_parser_new.h"
#include "pe_string_extractor.h"
#include "pe_structures.h"
#include "pe_ui_manager.h"
#include "pe_utils.h"
#include "language_manager.h"

#include <QComboBox>
#include <QDir>
#include <QFile>
#include <QFileDialog>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QLineEdit>
#include <QMetaObject>
#include <QPointer>
#include <QProgressBar>
#include <QPushButton>
#include <QSignalBlocker>
#include <QSpinBox>
#include <QTabWidget>
#include <QTreeWidget>
#include <QWidget>
#include <limits>

#include <QtConcurrent/QtConcurrent>

namespace {

QString normalizedSectionName(const IMAGE_SECTION_HEADER *section)
{
    if (!section) {
        return QStringLiteral("(unknown)");
    }
    const char *namePtr = reinterpret_cast<const char *>(section->Name);
    bool hasPrintable = false;
    for (int i = 0; i < 8; ++i) {
        const unsigned char c = static_cast<unsigned char>(namePtr[i]);
        if (c >= 32 && c <= 126) {
            hasPrintable = true;
            break;
        }
    }
    if (hasPrintable) {
        int len = 0;
        while (len < 8) {
            const unsigned char c = static_cast<unsigned char>(namePtr[len]);
            if (c == 0 || c < 32 || c > 126) {
                break;
            }
            ++len;
        }
        if (len > 0) {
            return QString::fromLatin1(namePtr, len);
        }
    }
    QByteArray nameBytes(namePtr, 8);
    return QStringLiteral("0x") + QString::fromLatin1(nameBytes.toHex()).toUpper();
}

} // namespace

StringsController::StringsController(UIManager *ui, QObject *parent)
    : QObject(parent), m_ui(ui)
{
    connect(&m_stringsExtractionWatcher, &QFutureWatcher<StringExtractionResult>::finished, this,
            &StringsController::handleExtractionFinished);
}

void StringsController::setParser(PEParserNew *parser)
{
    m_parser = parser;
}

void StringsController::setFilePath(const QString &path)
{
    m_filePath = path;
}

void StringsController::setFileLoaded(bool loaded)
{
    m_fileLoaded = loaded;
}

void StringsController::refresh()
{
    populate();
}

void StringsController::clear()
{
    stopExtractionSynchronously();
    if (m_ui && m_ui->m_stringsTree) {
        m_ui->m_stringsTree->clear();
    }
    m_extractedStrings.clear();
    if (m_ui && m_ui->m_stringsFilterEdit) {
        m_ui->m_stringsFilterEdit->clear();
    }
    if (m_ui && m_ui->m_stringsTypeCombo) {
        m_ui->m_stringsTypeCombo->setCurrentIndex(0);
    }
    if (m_ui && m_ui->m_stringsSectionCombo) {
        m_ui->m_stringsSectionCombo->clear();
        m_ui->m_stringsSectionCombo->addItem(LANG("UI/strings_all_sections"), QStringLiteral("__all__"));
    }
    if (m_ui && m_ui->m_stringsCancelButton) {
        m_ui->m_stringsCancelButton->setEnabled(false);
    }
    if (m_ui && m_ui->m_stringsExportButton) {
        m_ui->m_stringsExportButton->setEnabled(false);
    }
    m_stringsPopulated = false;
}

void StringsController::invalidate()
{
    m_stringsPopulated = false;
}

void StringsController::stopExtractionSynchronously()
{
    const bool hadWork = m_stringsExtractionRunning || m_stringsExtractionWatcher.isRunning();
    if (hadWork) {
        m_stringsExtractionWatcher.blockSignals(true);
        m_stringsExtractionWatcher.cancel();
        if (m_stringsExtractionWatcher.isRunning()) {
            m_stringsExtractionWatcher.waitForFinished();
        }
        m_stringsExtractionWatcher.blockSignals(false);
    }
    m_stringsExtractionRunning = false;

    if (m_ui) {
        if (m_ui->m_progressBar) {
            m_ui->m_progressBar->setVisible(false);
            m_ui->m_progressBar->setRange(0, 100);
            m_ui->m_progressBar->setValue(0);
            m_ui->m_progressBar->setFormat(QString());
        }
        if (m_ui->m_progressLabel) {
            m_ui->m_progressLabel->clear();
        }
        if (m_ui->m_stringsCancelButton) {
            m_ui->m_stringsCancelButton->setEnabled(false);
        }
    }
}

void StringsController::populateSectionCombo()
{
    if (!m_fileLoaded || !m_ui || !m_parser || !m_ui->m_stringsSectionCombo) {
        return;
    }

    QSignalBlocker blocker(m_ui->m_stringsSectionCombo);
    m_ui->m_stringsSectionCombo->clear();
    m_ui->m_stringsSectionCombo->addItem(LANG(QStringLiteral("UI/strings_all_sections")),
                                         QStringLiteral("__all__"));
    const QList<const IMAGE_SECTION_HEADER *> &sections = m_parser->getDataModel().getSections();
    for (const IMAGE_SECTION_HEADER *sec : sections) {
        if (!sec) {
            continue;
        }
        const QString label = normalizedSectionName(sec);
        m_ui->m_stringsSectionCombo->addItem(label, label);
    }
}

void StringsController::updateLanguageStrings()
{
    if (!m_ui) {
        return;
    }

    if (m_ui->m_stringsTree) {
        m_ui->m_stringsTree->setHeaderLabels({
            LANG("UI/strings_header_offset"),
            LANG("UI/strings_header_section"),
            LANG("UI/strings_header_type"),
            LANG("UI/strings_header_value")
        });
    }
    if (m_ui->m_stringsFilterEdit) {
        m_ui->m_stringsFilterEdit->setPlaceholderText(LANG("UI/strings_filter_placeholder"));
    }
    if (m_ui->m_stringsTypeCombo && m_ui->m_stringsTypeCombo->count() >= 6) {
        m_ui->m_stringsTypeCombo->setItemText(0, LANG("UI/strings_filter_type_all"));
        m_ui->m_stringsTypeCombo->setItemText(1, LANG("UI/strings_filter_type_ascii"));
        m_ui->m_stringsTypeCombo->setItemText(2, LANG("UI/strings_filter_type_unicode"));
        m_ui->m_stringsTypeCombo->setItemText(3, LANG("UI/strings_filter_type_url"));
        m_ui->m_stringsTypeCombo->setItemText(4, LANG("UI/strings_filter_type_ip"));
        m_ui->m_stringsTypeCombo->setItemText(5, LANG("UI/strings_filter_type_registry"));
        m_ui->m_stringsTypeCombo->setItemText(6, LANG("UI/strings_filter_type_command"));
    }
    if (m_ui->m_stringsMinLengthSpin) {
        m_ui->m_stringsMinLengthSpin->setPrefix(LANG("UI/strings_min_len_prefix"));
    }
    if (m_ui->m_stringsSectionCombo && m_ui->m_stringsSectionCombo->count() > 0) {
        m_ui->m_stringsSectionCombo->setItemText(0, LANG("UI/strings_all_sections"));
    }
    if (m_ui->m_stringsExportButton) {
        m_ui->m_stringsExportButton->setText(LANG("UI/button_export"));
    }
    if (m_ui->m_stringsCancelButton) {
        m_ui->m_stringsCancelButton->setText(LANG("UI/button_cancel"));
    }
}

void StringsController::handleFilterChanged(QObject *sender)
{
    if (!m_fileLoaded || !m_ui) {
        return;
    }
    const bool stringsTabActive =
        m_ui->m_analysisTabWidget && m_ui->m_analysisTabWidget->currentIndex() == 6;
    const bool senderTriggersExtraction =
        sender == m_ui->m_stringsMinLengthSpin || sender == m_ui->m_stringsSectionCombo;
    if (stringsTabActive && senderTriggersExtraction && !m_stringsExtractionRunning) {
        m_stringsPopulated = false;
        populate();
        return;
    }
    applyFilter();
}

void StringsController::handleExtractionFinished()
{
    m_stringsExtractionRunning = false;
    if (!m_ui) {
        return;
    }

    const QFuture<StringExtractionResult> fut = m_stringsExtractionWatcher.future();
    if (!fut.isFinished()) {
        return;
    }

    if (m_ui->m_progressBar) {
        m_ui->m_progressBar->setVisible(false);
        m_ui->m_progressBar->setRange(0, 100);
        m_ui->m_progressBar->setValue(0);
        m_ui->m_progressBar->setFormat(QString());
    }
    if (m_ui->m_progressLabel) {
        m_ui->m_progressLabel->clear();
    }
    if (m_ui->m_stringsCancelButton) {
        m_ui->m_stringsCancelButton->setEnabled(false);
    }
    if (m_ui->m_stringsExportButton) {
        m_ui->m_stringsExportButton->setEnabled(true);
    }

    if (fut.isCanceled()) {
        m_extractedStrings.clear();
        m_stringsPopulated = false;
        return;
    }

    if (!m_fileLoaded || !m_parser || !m_parser->isValid()) {
        m_extractedStrings.clear();
        m_stringsPopulated = false;
        return;
    }

    const StringExtractionResult strResult = fut.result();
    m_extractedStrings = strResult.strings;
    m_stringsPopulated = true;
    if (m_ui->m_stringsExportButton) {
        m_ui->m_stringsExportButton->setEnabled(!m_extractedStrings.isEmpty());
    }
    applyFilter();
}

void StringsController::handleCancelExtraction()
{
    if (!m_stringsExtractionRunning) {
        return;
    }
    m_stringsExtractionWatcher.cancel();
    m_stringsExtractionRunning = false;
    if (!m_ui) {
        return;
    }
    if (m_ui->m_progressBar) {
        m_ui->m_progressBar->setVisible(false);
        m_ui->m_progressBar->setRange(0, 100);
        m_ui->m_progressBar->setValue(0);
        m_ui->m_progressBar->setFormat(QString());
    }
    if (m_ui->m_progressLabel) {
        m_ui->m_progressLabel->setText(LANG("UI/strings_progress_cancelled"));
    }
    if (m_ui->m_stringsCancelButton) {
        m_ui->m_stringsCancelButton->setEnabled(false);
    }
    if (m_ui->m_stringsExportButton) {
        m_ui->m_stringsExportButton->setEnabled(!m_extractedStrings.isEmpty());
    }
}

void StringsController::handleExport()
{
    if (!m_ui || !m_ui->m_stringsTree) {
        return;
    }
    if (m_ui->m_stringsTree->topLevelItemCount() == 0) {
        emit statusMessageRequested(LANG("UI/strings_export_none"), 2500);
        return;
    }

    QWidget *parentWidget = qobject_cast<QWidget *>(parent());

    QString selectedFilter;
    const QString outPath = QFileDialog::getSaveFileName(
        parentWidget,
        LANG("UI/strings_export_dialog_title"),
        QDir::homePath() + QStringLiteral("/pehint_strings.csv"),
        LANG("UI/strings_export_filter"),
        &selectedFilter);
    if (outPath.isEmpty()) {
        return;
    }

    const QString nativeOutPath = QDir::toNativeSeparators(outPath);

    QString content;
    if (selectedFilter.contains(QStringLiteral("JSON"))) {
        QJsonArray arr;
        for (int i = 0; i < m_ui->m_stringsTree->topLevelItemCount(); ++i) {
            QTreeWidgetItem *it = m_ui->m_stringsTree->topLevelItem(i);
            if (!it) {
                continue;
            }
            QJsonObject o;
            o["offset"] = it->text(0);
            o["section"] = it->text(1);
            o["type"] = it->text(2);
            o["value"] = it->text(3);
            arr.append(o);
        }
        QJsonObject root;
        root["file"] = m_filePath;
        root["count"] = arr.size();
        root["strings"] = arr;
        content = QString::fromUtf8(QJsonDocument(root).toJson(QJsonDocument::Indented));
    } else if (selectedFilter.contains(QStringLiteral("Text"))) {
        QStringList lines;
        lines << LanguageManager::getInstance().getString(
            QStringLiteral("UI/strings_export_header_tsv"),
            QStringLiteral("offset\tsection\ttype\tvalue"));
        for (int i = 0; i < m_ui->m_stringsTree->topLevelItemCount(); ++i) {
            QTreeWidgetItem *it = m_ui->m_stringsTree->topLevelItem(i);
            if (!it) {
                continue;
            }
            lines << QStringLiteral("%1\t%2\t%3\t%4")
                         .arg(it->text(0), it->text(1), it->text(2), it->text(3));
        }
        content = lines.join(QLatin1Char('\n'));
    } else {
        QStringList lines;
        lines << LanguageManager::getInstance().getString(
            QStringLiteral("UI/strings_export_header_csv"),
            QStringLiteral("offset,section,type,value"));
        for (int i = 0; i < m_ui->m_stringsTree->topLevelItemCount(); ++i) {
            QTreeWidgetItem *it = m_ui->m_stringsTree->topLevelItem(i);
            if (!it) {
                continue;
            }
            auto csv = [](const QString &s) {
                QString v = s;
                v.replace('"', "\"\"");
                return QStringLiteral("\"%1\"").arg(v);
            };
            lines << QStringLiteral("%1,%2,%3,%4")
                         .arg(csv(it->text(0)), csv(it->text(1)), csv(it->text(2)), csv(it->text(3)));
        }
        content = lines.join(QLatin1Char('\n'));
    }

    QFile out(outPath);
    if (!out.open(QIODevice::WriteOnly | QIODevice::Truncate | QIODevice::Text)) {
        emit errorOccurred(LANG("UI/strings_export_error_title"),
                           LANG_PARAM("UI/strings_export_error_write", "path", nativeOutPath));
        return;
    }
    out.write(content.toUtf8());
    out.close();
    emit statusMessageRequested(LANG_PARAM("UI/strings_export_success", "path", nativeOutPath), 3500);
}

void StringsController::handleTreeItemDoubleClicked(QTreeWidgetItem *item, int /*column*/)
{
    if (!item || !m_ui || !m_fileLoaded) {
        return;
    }
    if (item->flags() == Qt::NoItemFlags) {
        return;
    }
    const QVariant v = item->data(0, Qt::UserRole);
    if (!v.isValid()) {
        return;
    }
    bool ok = false;
    const quint64 off64 = v.toULongLong(&ok);
    if (!ok || off64 > static_cast<quint64>(std::numeric_limits<quint32>::max())) {
        return;
    }
    const quint32 off = static_cast<quint32>(off64);
    int len = item->data(0, static_cast<int>(Qt::UserRole) + 1).toInt();
    if (len <= 0) {
        return;
    }
    emit requestHexHighlight(off, static_cast<quint32>(len));
}

void StringsController::applyFilter()
{
    if (!m_ui || !m_ui->m_stringsTree) {
        return;
    }
    m_ui->m_stringsTree->clear();

    if (m_stringsExtractionRunning) {
        QTreeWidgetItem *loading = new QTreeWidgetItem(m_ui->m_stringsTree);
        loading->setText(0, LANG("UI/strings_progress_extracting"));
        loading->setFirstColumnSpanned(true);
        loading->setFlags(Qt::NoItemFlags);
        return;
    }

    QString filterText;
    QString typeFilter = QStringLiteral("all");
    if (m_ui->m_stringsFilterEdit) {
        filterText = m_ui->m_stringsFilterEdit->text().trimmed();
    }
    if (m_ui->m_stringsTypeCombo) {
        typeFilter = m_ui->m_stringsTypeCombo->currentData().toString();
    }

    if (m_extractedStrings.isEmpty()) {
        QTreeWidgetItem *placeholder = new QTreeWidgetItem(m_ui->m_stringsTree);
        placeholder->setText(0, LanguageManager::getInstance().getString(
                                        QStringLiteral("UI/strings_list_empty"),
                                        QStringLiteral("No strings to display. Try Refresh or change filters.")));
        placeholder->setFirstColumnSpanned(true);
        placeholder->setFlags(Qt::NoItemFlags);
        return;
    }

    const bool sectionModelOk = m_fileLoaded && m_parser && m_parser->isValid();

    for (const ExtractedString &s : m_extractedStrings) {
        if (typeFilter == QLatin1String("ascii") && s.isUnicode) {
            continue;
        }
        if (typeFilter == QLatin1String("unicode") && !s.isUnicode) {
            continue;
        }
        if ((typeFilter == QLatin1String("url") || typeFilter == QLatin1String("ip")
             || typeFilter == QLatin1String("registry") || typeFilter == QLatin1String("command"))
            && !PEStringExtractor::matchesContentFilter(s.value, typeFilter)) {
            continue;
        }
        if (!filterText.isEmpty() && !s.value.contains(filterText, Qt::CaseInsensitive)) {
            continue;
        }

        QString displayValue = s.value;
        for (int i = 0; i < displayValue.size(); ++i) {
            QChar c = displayValue[i];
            if (c < QChar(0x20) && c != QChar('\t')) {
                displayValue[i] = QChar('.');
            } else if (c == QChar('\t')) {
                displayValue[i] = QChar(' ');
            }
        }
        if (displayValue.length() > 512) {
            displayValue = displayValue.left(512) + QStringLiteral("...");
        }
        QTreeWidgetItem *item = new QTreeWidgetItem(m_ui->m_stringsTree);
        item->setText(0, PEUtils::formatHexWidth(s.fileOffset, 8));
        QString sectionName = QStringLiteral("-");
        if (sectionModelOk) {
            for (const IMAGE_SECTION_HEADER *sec : m_parser->getDataModel().getSections()) {
                if (!sec) {
                    continue;
                }
                const quint32 start = sec->PointerToRawData;
                const quint32 end = start + sec->SizeOfRawData;
                if (s.fileOffset >= start && s.fileOffset < end) {
                    sectionName = normalizedSectionName(sec);
                    break;
                }
            }
        }
        item->setText(1, sectionName);
        item->setText(2, s.isUnicode ? LANG("UI/strings_type_unicode") : LANG("UI/strings_type_ascii"));
        item->setText(3, displayValue);
        if (s.value.length() > 512) {
            item->setToolTip(3, s.value);
        }
        item->setData(0, Qt::UserRole, static_cast<qulonglong>(s.fileOffset));
        const int byteLen = s.isUnicode ? (s.value.size() * 2) : s.value.size();
        item->setData(0, static_cast<int>(Qt::UserRole) + 1, byteLen);
    }
    if (m_ui->m_stringsExportButton) {
        m_ui->m_stringsExportButton->setEnabled(m_ui->m_stringsTree->topLevelItemCount() > 0);
    }
}

void StringsController::populate()
{
    if (!m_ui || !m_ui->m_stringsTree) {
        return;
    }
    if (!m_fileLoaded || !m_parser || !m_parser->isValid()) {
        return;
    }
    if (m_stringsPopulated && !m_stringsExtractionRunning) {
        if (!m_extractedStrings.isEmpty()) {
            applyFilter();
            return;
        }
        m_stringsPopulated = false;
    }
    if (m_stringsExtractionRunning) {
        return;
    }

    m_ui->m_stringsTree->clear();
    m_extractedStrings.clear();
    const int minLen =
        (m_ui->m_stringsMinLengthSpin ? m_ui->m_stringsMinLengthSpin->value() : 4);
    QString selectedSection =
        (m_ui->m_stringsSectionCombo ? m_ui->m_stringsSectionCombo->currentData().toString()
                                     : QStringLiteral("__all__"));
    if (selectedSection.isEmpty()) {
        selectedSection = QStringLiteral("__all__");
    }
    if (m_ui->m_stringsCancelButton) {
        m_ui->m_stringsCancelButton->setEnabled(true);
    }
    if (m_ui->m_stringsExportButton) {
        m_ui->m_stringsExportButton->setEnabled(false);
    }
    if (m_ui->m_progressBar) {
        m_ui->m_progressBar->setVisible(true);
        m_ui->m_progressBar->setRange(0, 100);
        m_ui->m_progressBar->setValue(0);
        m_ui->m_progressBar->setTextVisible(true);
        m_ui->m_progressBar->setFormat(QStringLiteral("%p%"));
    }
    const QString stringsProgressMsg = LANG("UI/strings_progress_extracting");
    if (m_ui->m_progressLabel) {
        m_ui->m_progressLabel->setText(QStringLiteral("0% — %1").arg(stringsProgressMsg));
    }

    m_stringsExtractionRunning = true;
    m_stringsPopulated = false;

    struct SectionSlice {
        QString name;
        quint32 offset;
        quint32 size;
    };
    QList<SectionSlice> sectionSlices;
    const QList<const IMAGE_SECTION_HEADER *> &sections = m_parser->getDataModel().getSections();
    for (const IMAGE_SECTION_HEADER *sec : sections) {
        if (!sec) {
            continue;
        }
        SectionSlice s;
        s.name = normalizedSectionName(sec);
        s.offset = sec->PointerToRawData;
        s.size = sec->SizeOfRawData;
        sectionSlices.append(s);
    }

    const QString filePath = m_filePath;
    const QPointer<StringsController> self(this);
    m_stringsExtractionWatcher.setFuture(QtConcurrent::run(
        [self, filePath, minLen, selectedSection, sectionSlices, stringsProgressMsg]() {
            StringExtractionResult out;
            out.minLength = minLen;

            const auto pushProgress = [self, stringsProgressMsg](int uiPercent) {
                if (!self) {
                    return;
                }
                const int p = qBound(0, uiPercent, 100);
                QMetaObject::invokeMethod(
                    self.data(),
                    [self, p, stringsProgressMsg]() {
                        if (!self || !self->m_ui || !self->m_ui->m_progressBar) {
                            return;
                        }
                        self->m_ui->m_progressBar->setRange(0, 100);
                        self->m_ui->m_progressBar->setValue(p);
                        if (self->m_ui->m_progressLabel) {
                            self->m_ui->m_progressLabel->setText(
                                QStringLiteral("%1% — %2").arg(p).arg(stringsProgressMsg));
                        }
                    },
                    Qt::QueuedConnection);
            };

            const auto extractProgress = [&pushProgress](int extractPct) {
                pushProgress(5 + (extractPct * 95) / 100);
            };

            QFile f(filePath);
            if (!f.open(QIODevice::ReadOnly)) {
                return out;
            }
            const QByteArray fullData = f.readAll();
            f.close();
            if (fullData.isEmpty()) {
                return out;
            }

            pushProgress(5);

            if (selectedSection != QStringLiteral("__all__")) {
                for (const auto &s : sectionSlices) {
                    if (s.name.compare(selectedSection, Qt::CaseInsensitive) != 0) {
                        continue;
                    }
                    if (s.offset >= static_cast<quint32>(fullData.size())) {
                        break;
                    }
                    const quint32 cappedSize =
                        qMin(s.size, static_cast<quint32>(fullData.size() - s.offset));
                    StringExtractionResult sectionRes = PEStringExtractor::extractFromData(
                        fullData.mid(static_cast<int>(s.offset), static_cast<int>(cappedSize)), minLen,
                        extractProgress);
                    for (ExtractedString e : sectionRes.strings) {
                        e.fileOffset += s.offset;
                        out.strings.append(e);
                    }
                    pushProgress(100);
                    return out;
                }
                pushProgress(100);
                return out;
            }

            out = PEStringExtractor::extractFromData(fullData, minLen, extractProgress);
            pushProgress(100);
            return out;
        }));
}
