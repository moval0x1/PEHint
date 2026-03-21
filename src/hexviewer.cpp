#include "hexviewer.h"
#include "virtual_hex_widget.h"
#include "language_manager.h"
#include "pe_utils.h"

#include <QApplication>
#include <QClipboard>
#include <QDialog>
#include <QDialogButtonBox>
#include <QHBoxLayout>
#include <QCheckBox>
#include <QGroupBox>
#include <QKeySequence>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QSpinBox>
#include <QVBoxLayout>
#include <QSignalBlocker>
#include <QFocusEvent>
#include <QPalette>
#include <QStyle>
#include <limits>

namespace {

QString hexUiString(const QString &key, const QString &englishFallback)
{
    return LanguageManager::getInstance().getString(key, englishFallback);
}

} // namespace

HexViewer::HexViewer(QWidget *parent)
    : QWidget(parent)
{
    setupUI();
    setupConnections();
}

HexViewer::~HexViewer() = default;

void HexViewer::applyHexFont()
{
    QFont hf;
    const QString fam = LANG("UI/font_consolas");
    hf.setFamily(fam.isEmpty() ? QStringLiteral("Consolas") : fam);
    hf.setStyleHint(QFont::Monospace);
    hf.setFixedPitch(true);
    hf.setPointSize(9);
    if (m_virtualHex) {
        m_virtualHex->setFont(hf);
    }
}

void HexViewer::setupUI()
{
    auto *mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(4, 4, 4, 4);

    auto *controlLayout = new QHBoxLayout();
    m_offsetLabel = new QLabel(LANG("UI/hex_go_to_offset"), this);
    m_offsetSpinBox = new QSpinBox(this);
    m_offsetSpinBox->setRange(0, 0);
    m_offsetSpinBox->setPrefix(LANG("UI/hex_prefix"));
    m_offsetSpinBox->setDisplayIntegerBase(16);
    m_offsetSpinBox->setMaximumWidth(120);

    m_bytesLabel = new QLabel(LANG("UI/hex_bytes_per_line"), this);
    m_bytesPerLineSpinBox = new QSpinBox(this);
    m_bytesPerLineSpinBox->setRange(8, 64);
    m_bytesPerLineSpinBox->setValue(16);
    m_bytesPerLineSpinBox->setMaximumWidth(80);

    m_showOffsetButton = new QPushButton(LANG("UI/hex_show_offset"), this);
    m_showOffsetButton->setCheckable(true);
    m_showOffsetButton->setChecked(true);

    m_showAsciiButton = new QPushButton(LANG("UI/hex_show_ascii"), this);
    m_showAsciiButton->setCheckable(true);
    m_showAsciiButton->setChecked(true);

    m_copyHexButton = new QPushButton(LANG("UI/hex_copy_hex"), this);
    m_copyHexButton->setIcon(QIcon(":/images/imgs/copy.png"));
    m_copyHexButton->setToolTip(LANG("UI/hex_copy_hex_tooltip"));
    m_copyAsciiButton = new QPushButton(LANG("UI/hex_copy_ascii"), this);
    m_copyAsciiButton->setIcon(QIcon(":/images/imgs/copy.png"));
    m_copyAsciiButton->setToolTip(LANG("UI/hex_copy_ascii_tooltip"));
    m_findButton = new QPushButton(LANG("UI/button_find"), this);
    m_findButton->setIcon(QIcon(":/images/imgs/search.png"));

    m_findNextButton = new QPushButton(this);
    m_findNextButton->setIcon(style()->standardIcon(QStyle::SP_ArrowDown));
    m_findNextButton->setIconSize(QSize(16, 16));
    m_findNextButton->setToolTip(LANG("UI/hex_search_find_next"));
    m_findNextButton->setAccessibleName(LANG("UI/hex_search_find_next"));
    m_findNextButton->setMaximumWidth(34);
    m_findNextButton->setEnabled(false);

    m_findPrevButton = new QPushButton(this);
    m_findPrevButton->setIcon(style()->standardIcon(QStyle::SP_ArrowUp));
    m_findPrevButton->setIconSize(QSize(16, 16));
    m_findPrevButton->setToolTip(LANG("UI/hex_search_find_previous"));
    m_findPrevButton->setAccessibleName(LANG("UI/hex_search_find_previous"));
    m_findPrevButton->setMaximumWidth(34);
    m_findPrevButton->setEnabled(false);

    controlLayout->addWidget(m_offsetLabel);
    controlLayout->addWidget(m_offsetSpinBox);
    controlLayout->addWidget(m_bytesLabel);
    controlLayout->addWidget(m_bytesPerLineSpinBox);
    controlLayout->addStretch();
    controlLayout->addWidget(m_showOffsetButton);
    controlLayout->addWidget(m_showAsciiButton);
    controlLayout->addWidget(m_copyHexButton);
    controlLayout->addWidget(m_copyAsciiButton);
    controlLayout->addWidget(m_findButton);
    controlLayout->addWidget(m_findPrevButton);
    controlLayout->addWidget(m_findNextButton);

    mainLayout->addLayout(controlLayout);

    m_virtualHex = new VirtualHexWidget(this);
    {
        QPalette vp = m_virtualHex->viewport()->palette();
        vp.setColor(QPalette::Base, QColor(255, 255, 255));
        vp.setColor(QPalette::Text, QColor(0, 0, 0));
        m_virtualHex->viewport()->setPalette(vp);
        m_virtualHex->viewport()->setAutoFillBackground(true);
    }
    applyHexFont();
    m_virtualHex->setHeaderLabels(LANG("UI/hex_header_offset_label"), LANG("UI/hex_header_decoded_label"));
    m_virtualHex->setBytesPerLine(m_bytesPerLine);
    m_virtualHex->setShowOffset(m_showOffset);
    m_virtualHex->setShowAscii(m_showAscii);
    mainLayout->addWidget(m_virtualHex, 1);

    auto *statusLayout = new QHBoxLayout();
    m_statusLabel = new QLabel(QString(), this);
    m_statusLabel->setObjectName(QStringLiteral("hexViewerStatusLabel"));
    m_statusLabel->setMinimumWidth(120);
    m_statusLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    statusLayout->addWidget(m_statusLabel);
    statusLayout->addStretch();
    mainLayout->addLayout(statusLayout);
}

void HexViewer::setupConnections()
{
    connect(m_offsetSpinBox, QOverload<int>::of(&QSpinBox::valueChanged), this, &HexViewer::onOffsetChanged);
    connect(m_bytesPerLineSpinBox, QOverload<int>::of(&QSpinBox::valueChanged), this,
            &HexViewer::onBytesPerLineChanged);
    connect(m_showOffsetButton, &QPushButton::toggled, this, &HexViewer::onShowOffsetToggled);
    connect(m_showAsciiButton, &QPushButton::toggled, this, &HexViewer::onShowAsciiToggled);
    connect(m_copyHexButton, &QPushButton::clicked, this, &HexViewer::onCopyHexSelection);
    connect(m_copyAsciiButton, &QPushButton::clicked, this, &HexViewer::onCopyAsciiSelection);
    connect(m_findButton, &QPushButton::clicked, this, &HexViewer::onFindText);
    connect(m_findNextButton, &QPushButton::clicked, this, &HexViewer::findNext);
    connect(m_findPrevButton, &QPushButton::clicked, this, &HexViewer::findPrevious);

    connect(m_virtualHex, &VirtualHexWidget::selectionChanged, this, &HexViewer::updateSelectionOffsetStatus);
    connect(m_virtualHex, &VirtualHexWidget::byteClicked, this, [this](qint64 off, int len) {
        clearHighlights();
        {
            QSignalBlocker b(m_offsetSpinBox);
            const int mx = std::numeric_limits<int>::max();
            m_offsetSpinBox->setValue(static_cast<int>(qMin(off, static_cast<qint64>(mx))));
        }
        emit byteClicked(off, len);
    });
}

void HexViewer::syncHighlightsToWidget()
{
    if (!m_virtualHex) {
        return;
    }
    QList<VirtualHexWidget::HighlightSeg> segs;
    segs.reserve(m_highlights.size());
    for (const HighlightRange &h : m_highlights) {
        VirtualHexWidget::HighlightSeg s;
        s.start = h.startOffset;
        s.length = h.length;
        s.color = h.color;
        if (s.color.alpha() < 150) {
            s.color.setAlpha(200);
        }
        segs.append(s);
    }
    m_virtualHex->setHighlights(segs);
}

void HexViewer::setData(const QByteArray &data, qint64 logicalTotalBytes)
{
    m_data = data;
    m_logicalDataSize = (logicalTotalBytes >= 0) ? logicalTotalBytes : static_cast<qint64>(data.size());

    const bool hasData = !data.isEmpty();
    m_findButton->setEnabled(hasData);
    m_offsetSpinBox->setEnabled(hasData);
    m_bytesPerLineSpinBox->setEnabled(hasData);
    m_showOffsetButton->setEnabled(hasData);
    m_showAsciiButton->setEnabled(hasData);
    m_copyHexButton->setEnabled(hasData);
    m_copyAsciiButton->setEnabled(hasData);

    clearSearchResults(false);

    {
        QSignalBlocker blockOffset(m_offsetSpinBox);
        updateDisplay();
        const qint64 maxByteIndex = data.isEmpty() ? 0 : qMax<qint64>(0, data.size() - 1);
        const int spinMax = data.isEmpty()
            ? 0
            : static_cast<int>(qMin(maxByteIndex, static_cast<qint64>(std::numeric_limits<int>::max())));
        m_offsetSpinBox->setRange(0, spinMax);
        int v = m_offsetSpinBox->value();
        v = qBound(0, v, spinMax);
        m_offsetSpinBox->setValue(v);
    }

    emit hexContentReady();
}

qint64 HexViewer::logicalDataSize() const
{
    return m_logicalDataSize >= 0 ? m_logicalDataSize : static_cast<qint64>(m_data.size());
}

void HexViewer::clear()
{
    m_data.clear();
    m_logicalDataSize = -1;
    m_highlights.clear();
    if (m_virtualHex) {
        m_virtualHex->setData(nullptr);
        m_virtualHex->clearHighlights();
    }
    {
        QSignalBlocker block(m_offsetSpinBox);
        m_offsetSpinBox->setRange(0, 0);
    }
    clearSearchResults();
    emit hexContentReady();
}

void HexViewer::goToOffset(qint64 offset)
{
    if (!m_virtualHex || m_data.isEmpty() || offset < 0 || offset >= m_data.size()) {
        return;
    }
    {
        QSignalBlocker b(m_offsetSpinBox);
        m_offsetSpinBox->setValue(static_cast<int>(qMin(offset, static_cast<qint64>(std::numeric_limits<int>::max()))));
    }
    m_virtualHex->scrollToByteOffset(offset, false);
}

void HexViewer::setBytesPerLine(int bytesPerLine)
{
    m_bytesPerLine = qBound(8, bytesPerLine, 64);
    m_bytesPerLineSpinBox->setValue(m_bytesPerLine);
    updateDisplay();
}

void HexViewer::setShowAscii(bool show)
{
    m_showAscii = show;
    m_showAsciiButton->setChecked(show);
    if (m_virtualHex) {
        m_virtualHex->setShowAscii(show);
    }
}

void HexViewer::setShowOffset(bool show)
{
    m_showOffset = show;
    m_showOffsetButton->setChecked(show);
    if (m_virtualHex) {
        m_virtualHex->setShowOffset(show);
    }
}

void HexViewer::updateDisplay()
{
    if (m_data.isEmpty()) {
        m_highlights.clear();
        if (m_virtualHex) {
            m_virtualHex->setData(nullptr);
            m_virtualHex->clearHighlights();
        }
        if (m_statusLabel) {
            m_statusLabel->clear();
        }
        return;
    }
    if (m_virtualHex) {
        m_virtualHex->setBytesPerLine(m_bytesPerLine);
        m_virtualHex->setShowOffset(m_showOffset);
        m_virtualHex->setShowAscii(m_showAscii);
        m_virtualHex->setData(&m_data);
        syncHighlightsToWidget();
    }
    updateSelectionOffsetStatus();
}

void HexViewer::highlightRange(quint32 startOffset, quint32 length, const QColor &color)
{
    if (m_data.isEmpty() || startOffset >= static_cast<quint32>(m_data.size()) || !m_virtualHex) {
        return;
    }
    m_highlights.clear();
    HighlightRange h;
    h.startOffset = startOffset;
    h.length = qMin(length, static_cast<quint32>(m_data.size() - startOffset));
    QColor highlightColor = color;
    if (highlightColor.alpha() < 150) {
        highlightColor.setAlpha(200);
    }
    h.color = highlightColor;
    m_highlights.append(h);
    syncHighlightsToWidget();
    const qint64 go = static_cast<qint64>(startOffset);
    goToOffset(go);
}

void HexViewer::clearHighlights()
{
    m_highlights.clear();
    if (m_virtualHex) {
        m_virtualHex->clearHighlights();
    }
}

void HexViewer::onOffsetChanged(int value)
{
    if (m_virtualHex && !m_data.isEmpty()) {
        m_virtualHex->scrollToByteOffset(static_cast<qint64>(value), false);
    }
    updateSelectionOffsetStatus();
}

void HexViewer::onBytesPerLineChanged(int value)
{
    m_bytesPerLine = qBound(8, value, 64);
    updateDisplay();
}

void HexViewer::onShowAsciiToggled(bool checked)
{
    m_showAscii = checked;
    if (m_virtualHex) {
        m_virtualHex->setShowAscii(checked);
    }
}

void HexViewer::onShowOffsetToggled(bool checked)
{
    m_showOffset = checked;
    if (m_virtualHex) {
        m_virtualHex->setShowOffset(checked);
    }
}

void HexViewer::onCopyHexSelection()
{
    qint64 a = 0;
    qint64 b = 0;
    if (!selectedFileByteRange(a, b)) {
        return;
    }
    QApplication::clipboard()->setText(clipboardHexForRange(a, b));
}

void HexViewer::onCopyAsciiSelection()
{
    qint64 a = 0;
    qint64 b = 0;
    if (!selectedFileByteRange(a, b)) {
        return;
    }
    QApplication::clipboard()->setText(clipboardAsciiForRange(a, b));
}

bool HexViewer::selectedFileByteRange(qint64 &start, qint64 &end) const
{
    if (!m_virtualHex || m_data.isEmpty()) {
        return false;
    }
    if (!m_virtualHex->hasSelection()) {
        // No click in hex yet: use "Go to offset" as the implicit caret (avoids bogus byte 0).
        if (!m_offsetSpinBox) {
            return false;
        }
        const qint64 off = static_cast<qint64>(m_offsetSpinBox->value());
        if (off < 0 || off >= m_data.size()) {
            return false;
        }
        start = end = off;
        return true;
    }
    start = m_virtualHex->selectionStart();
    end = m_virtualHex->selectionEnd();
    if (start > end) {
        const qint64 t = start;
        start = end;
        end = t;
    }
    if (start < 0 || start >= m_data.size()) {
        return false;
    }
    end = qMin(end, static_cast<qint64>(m_data.size() - 1));
    return true;
}


QString HexViewer::clipboardHexForRange(qint64 start, qint64 end) const
{
    if (!m_virtualHex) {
        return {};
    }
    return m_virtualHex->hexClipboardText(start, end);
}

QString HexViewer::clipboardAsciiForRange(qint64 start, qint64 end) const
{
    if (!m_virtualHex) {
        return {};
    }
    return m_virtualHex->asciiClipboardText(start, end);
}

void HexViewer::updateSelectionOffsetStatus()
{
    if (!m_statusLabel || m_data.isEmpty() || !m_virtualHex) {
        return;
    }
    if (!m_virtualHex->hasSelection()) {
        const qint64 off = m_offsetSpinBox ? static_cast<qint64>(m_offsetSpinBox->value()) : 0LL;
        if (off >= 0 && off < m_data.size()) {
            QMap<QString, QString> p;
            p[QStringLiteral("offset")] = PEUtils::formatHexWidth(static_cast<quint64>(off), 8);
            m_statusLabel->setText(LANG_PARAMS(QStringLiteral("UI/hex_status_at_offset"), p));
        } else {
            m_statusLabel->clear();
        }
        return;
    }
    qint64 start = m_virtualHex->selectionStart();
    qint64 end = m_virtualHex->selectionEnd();
    if (start > end) {
        const qint64 t = start;
        start = end;
        end = t;
    }
    end = qMin(end, static_cast<qint64>(m_data.size() - 1));
    if (start == end) {
        QMap<QString, QString> p;
        p[QStringLiteral("offset")] = PEUtils::formatHexWidth(static_cast<quint64>(start), 8);
        m_statusLabel->setText(LANG_PARAMS(QStringLiteral("UI/hex_status_at_offset"), p));
        return;
    }
    const qint64 count = end - start + 1;
    QMap<QString, QString> p;
    p[QStringLiteral("start")] = PEUtils::formatHexWidth(static_cast<quint64>(start), 8);
    p[QStringLiteral("end")] = PEUtils::formatHexWidth(static_cast<quint64>(end), 8);
    p[QStringLiteral("count")] = QString::number(count);
    m_statusLabel->setText(LANG_PARAMS(QStringLiteral("UI/hex_selection_range"), p));
}

void HexViewer::focusInEvent(QFocusEvent *event)
{
    QWidget::focusInEvent(event);
}

void HexViewer::focusOutEvent(QFocusEvent *event)
{
    QWidget::focusOutEvent(event);
}

void HexViewer::updateLanguage()
{
    if (m_offsetSpinBox) {
        QSignalBlocker blockOffset(m_offsetSpinBox);
        m_offsetSpinBox->setPrefix(LANG("UI/hex_prefix"));
    }
    if (m_showOffsetButton) {
        m_showOffsetButton->setText(LANG("UI/hex_show_offset"));
    }
    if (m_showAsciiButton) {
        m_showAsciiButton->setText(LANG("UI/hex_show_ascii"));
    }
    if (m_copyHexButton) {
        m_copyHexButton->setText(LANG("UI/hex_copy_hex"));
        m_copyHexButton->setToolTip(LANG("UI/hex_copy_hex_tooltip"));
    }
    if (m_copyAsciiButton) {
        m_copyAsciiButton->setText(LANG("UI/hex_copy_ascii"));
        m_copyAsciiButton->setToolTip(LANG("UI/hex_copy_ascii_tooltip"));
    }
    if (m_findButton) {
        m_findButton->setText(LANG("UI/button_find"));
    }
    if (m_findNextButton) {
        m_findNextButton->setToolTip(LANG("UI/hex_search_find_next"));
    }
    if (m_findPrevButton) {
        m_findPrevButton->setToolTip(LANG("UI/hex_search_find_previous"));
    }
    if (m_offsetLabel) {
        m_offsetLabel->setText(LANG("UI/hex_go_to_offset"));
    }
    if (m_bytesLabel) {
        m_bytesLabel->setText(LANG("UI/hex_bytes_per_line"));
    }
    if (m_virtualHex) {
        m_virtualHex->setHeaderLabels(LANG("UI/hex_header_offset_label"), LANG("UI/hex_header_decoded_label"));
    }
    applyHexFont();
    if (!m_data.isEmpty()) {
        updateDisplay();
    } else {
        updateSelectionOffsetStatus();
    }
}

// --- Search ---

void HexViewer::findHexPattern(const QString &pattern, bool caseSensitive)
{
    if (m_data.isEmpty() || pattern.isEmpty()) {
        return;
    }
    const QByteArray hexPattern = parseHexPattern(pattern);
    if (hexPattern.isEmpty()) {
        QMessageBox::warning(this,
                             hexUiString(QStringLiteral("UI/hex_search_invalid_pattern"), QStringLiteral("Invalid Pattern")),
                             hexUiString(QStringLiteral("UI/hex_search_invalid_message"),
                                         QStringLiteral("Invalid hexadecimal pattern. Please use format like: 90, 0x4D5A, or 90 90 90")));
        return;
    }
    m_lastSearchPattern = hexPattern;
    m_lastSearchCaseSensitive = caseSensitive;
    m_searchResults = findPatternInData(hexPattern, caseSensitive);
    m_currentSearchIndex = -1;

    if (m_searchResults.isEmpty()) {
        QMessageBox::information(
            this,
            hexUiString(QStringLiteral("UI/hex_search_no_results"), QStringLiteral("Search Results")),
            LanguageManager::getInstance().getString(QStringLiteral("UI/hex_search_no_matches"),
                                                     QMap<QString, QString>{{QStringLiteral("pattern"), pattern}},
                                                     QStringLiteral("No matches found for pattern: {pattern}")));
        clearSearchResults();
        return;
    }

    QMap<QString, QString> params;
    params[QStringLiteral("count")] = QString::number(m_searchResults.size());
    params[QStringLiteral("pattern")] = pattern;
    QMessageBox::information(
        this,
        hexUiString(QStringLiteral("UI/hex_search_no_results"), QStringLiteral("Search Results")),
        LanguageManager::getInstance().getString(QStringLiteral("UI/hex_search_results_found"), params,
                                                 QStringLiteral("Found {count} match(es) for pattern: {pattern}")));

    m_findNextButton->setEnabled(true);
    m_findPrevButton->setEnabled(true);
    highlightSearchResults();
    goToSearchResult(0);
}

void HexViewer::findTextPattern(const QString &text, bool caseSensitive)
{
    if (m_data.isEmpty()) {
        return;
    }
    const QString trimmed = text.trimmed();
    if (trimmed.isEmpty()) {
        QMessageBox::warning(this,
                             hexUiString(QStringLiteral("UI/hex_search_invalid_pattern"), QStringLiteral("Invalid Pattern")),
                             hexUiString(QStringLiteral("UI/hex_search_pattern_empty"),
                                         QStringLiteral("Please enter a search pattern.")));
        return;
    }
    const QByteArray needle = trimmed.toUtf8();
    m_lastSearchPattern = needle;
    m_lastSearchCaseSensitive = caseSensitive;
    m_searchResults = findPatternInData(needle, caseSensitive);
    m_currentSearchIndex = -1;

    if (m_searchResults.isEmpty()) {
        QMessageBox::information(
            this,
            hexUiString(QStringLiteral("UI/hex_search_no_results"), QStringLiteral("Search Results")),
            LanguageManager::getInstance().getString(QStringLiteral("UI/hex_search_no_matches"),
                                                     QMap<QString, QString>{{QStringLiteral("pattern"), trimmed}},
                                                     QStringLiteral("No matches found for pattern: {pattern}")));
        clearSearchResults();
        return;
    }

    QMap<QString, QString> params;
    params[QStringLiteral("count")] = QString::number(m_searchResults.size());
    params[QStringLiteral("pattern")] = trimmed;
    QMessageBox::information(
        this,
        hexUiString(QStringLiteral("UI/hex_search_no_results"), QStringLiteral("Search Results")),
        LanguageManager::getInstance().getString(QStringLiteral("UI/hex_search_results_found"), params,
                                                 QStringLiteral("Found {count} match(es) for pattern: {pattern}")));

    m_findNextButton->setEnabled(true);
    m_findPrevButton->setEnabled(true);
    highlightSearchResults();
    goToSearchResult(0);
}

QByteArray HexViewer::parseHexPattern(const QString &pattern)
{
    QString cleanPattern = pattern.trimmed();
    cleanPattern = cleanPattern.remove("0x", Qt::CaseInsensitive);
    cleanPattern = cleanPattern.remove("h", Qt::CaseInsensitive);
    cleanPattern = cleanPattern.remove("\\x");
    cleanPattern = cleanPattern.remove(" ");
    cleanPattern = cleanPattern.remove("\t");
    cleanPattern = cleanPattern.remove(",");
    cleanPattern = cleanPattern.remove(";");
    if (cleanPattern.isEmpty() || cleanPattern.length() % 2 != 0) {
        return QByteArray();
    }
    QByteArray result;
    for (int i = 0; i < cleanPattern.length(); i += 2) {
        const QString byteStr = cleanPattern.mid(i, 2);
        bool ok = false;
        const char byte = static_cast<char>(byteStr.toInt(&ok, 16));
        if (!ok) {
            return QByteArray();
        }
        result.append(byte);
    }
    return result;
}

QList<HexViewer::SearchResult> HexViewer::findPatternInData(const QByteArray &pattern, bool caseSensitive)
{
    QList<SearchResult> results;
    if (pattern.isEmpty() || m_data.isEmpty()) {
        return results;
    }
    QByteArray searchData = m_data;
    QByteArray searchPattern = pattern;
    if (!caseSensitive) {
        searchData = searchData.toLower();
        searchPattern = searchPattern.toLower();
    }
    int offset = 0;
    while (true) {
        const int index = searchData.indexOf(searchPattern, offset);
        if (index == -1) {
            break;
        }
        SearchResult result;
        result.offset = index;
        result.length = pattern.size();
        result.pattern = pattern;
        results.append(result);
        offset = index + 1;
    }
    return results;
}

void HexViewer::findNext()
{
    if (m_searchResults.isEmpty()) {
        return;
    }
    m_currentSearchIndex = (m_currentSearchIndex + 1) % m_searchResults.size();
    goToSearchResult(m_currentSearchIndex);
}

void HexViewer::findPrevious()
{
    if (m_searchResults.isEmpty()) {
        return;
    }
    m_currentSearchIndex = (m_currentSearchIndex - 1 + m_searchResults.size()) % m_searchResults.size();
    goToSearchResult(m_currentSearchIndex);
}

void HexViewer::clearSearchResults(bool rebuildHex)
{
    Q_UNUSED(rebuildHex);
    m_searchResults.clear();
    m_currentSearchIndex = -1;
    m_lastSearchPattern.clear();
    m_findNextButton->setEnabled(false);
    m_findPrevButton->setEnabled(false);
    if (rebuildHex) {
        clearHighlights();
    } else {
        m_highlights.clear();
        syncHighlightsToWidget();
    }
}

void HexViewer::highlightSearchResults()
{
    if (m_searchResults.isEmpty()) {
        return;
    }
    m_highlights.clear();
    const QColor searchColor(255, 0, 255, 150);
    for (const SearchResult &result : m_searchResults) {
        if (result.offset < 0 || result.offset >= m_data.size()) {
            continue;
        }
        HighlightRange h;
        h.startOffset = static_cast<quint32>(result.offset);
        h.length = static_cast<quint32>(qMin<qint64>(result.length, m_data.size() - result.offset));
        h.color = searchColor;
        m_highlights.append(h);
    }
    syncHighlightsToWidget();
}

void HexViewer::goToSearchResult(int index)
{
    if (index < 0 || index >= m_searchResults.size()) {
        return;
    }
    const SearchResult &result = m_searchResults[index];
    m_currentSearchIndex = index;
    goToOffset(result.offset);

    QMap<QString, QString> params;
    params[QStringLiteral("current")] = QString::number(index + 1);
    params[QStringLiteral("total")] = QString::number(m_searchResults.size());
    params[QStringLiteral("offset")] = QString::number(result.offset, 16);
    if (m_statusLabel) {
        m_statusLabel->setText(LANG_PARAMS("UI/hex_search_result_status", params));
    }
}

void HexViewer::onFindText()
{
    QDialog searchDialog(this);
    searchDialog.setWindowTitle(hexUiString(QStringLiteral("UI/hex_find_text"), QStringLiteral("Find Text")));
    searchDialog.setModal(true);
    searchDialog.resize(400, 200);

    auto *mainLayout = new QVBoxLayout(&searchDialog);
    auto *patternLayout = new QHBoxLayout();
    auto *patternLabel = new QLabel(hexUiString(QStringLiteral("UI/hex_search_pattern"), QStringLiteral("Search Pattern:")), &searchDialog);
    auto *patternEdit = new QLineEdit(&searchDialog);
    patternEdit->setMinimumWidth(250);
    patternLayout->addWidget(patternLabel);
    patternLayout->addWidget(patternEdit);

    auto *optionsLayout = new QHBoxLayout();
    auto *caseSensitiveCheck = new QCheckBox(hexUiString(QStringLiteral("UI/hex_search_case_sensitive"), QStringLiteral("Case Sensitive")), &searchDialog);
    auto *hexOnlyCheck = new QCheckBox(hexUiString(QStringLiteral("UI/hex_search_hex_only"), QStringLiteral("Hex Only (no spaces)")), &searchDialog);
    hexOnlyCheck->setChecked(true);
    optionsLayout->addWidget(caseSensitiveCheck);
    optionsLayout->addWidget(hexOnlyCheck);

    const auto refreshPlaceholder = [&]() {
        if (hexOnlyCheck->isChecked()) {
            patternEdit->setPlaceholderText(hexUiString(QStringLiteral("UI/hex_search_placeholder"),
                                                        QStringLiteral("Enter hex pattern (e.g., 90, 0x4D5A, 90 90 90)")));
        } else {
            patternEdit->setPlaceholderText(hexUiString(QStringLiteral("UI/hex_search_placeholder_text"),
                                                        QStringLiteral("Enter text (searched as UTF-8 bytes), e.g. KERNEL32")));
        }
    };
    QObject::connect(hexOnlyCheck, &QCheckBox::toggled, &searchDialog, [refreshPlaceholder](bool) { refreshPlaceholder(); });
    refreshPlaceholder();

    auto *buttonLayout = new QHBoxLayout();
    auto *findButton = new QPushButton(hexUiString(QStringLiteral("UI/hex_search_find"), QStringLiteral("Find")), &searchDialog);
    auto *cancelButton = new QPushButton(hexUiString(QStringLiteral("UI/hex_search_cancel"), QStringLiteral("Cancel")), &searchDialog);
    findButton->setDefault(true);
    buttonLayout->addWidget(findButton);
    buttonLayout->addWidget(cancelButton);

    mainLayout->addLayout(patternLayout);
    mainLayout->addLayout(optionsLayout);
    mainLayout->addLayout(buttonLayout);

    connect(findButton, &QPushButton::clicked, &searchDialog, &QDialog::accept);
    connect(cancelButton, &QPushButton::clicked, &searchDialog, &QDialog::reject);
    patternEdit->setFocus();

    if (searchDialog.exec() == QDialog::Accepted) {
        const QString pattern = patternEdit->text();
        if (pattern.trimmed().isEmpty()) {
            return;
        }
        if (hexOnlyCheck->isChecked()) {
            findHexPattern(pattern, caseSensitiveCheck->isChecked());
        } else {
            findTextPattern(pattern, caseSensitiveCheck->isChecked());
        }
    }
}
