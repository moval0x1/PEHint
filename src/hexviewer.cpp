#include "hexviewer.h"
#include "language_manager.h"
#include <QTextCursor>
#include <QTextCharFormat>
#include <QScrollBar>
#include <QApplication>
#include <QClipboard>
#include <QInputDialog>
#include <QMessageBox>
#include <QFontDatabase>
#include <QDialog>
#include <QLineEdit>
#include <QCheckBox>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>

HexViewer::HexViewer(QWidget *parent)
    : QWidget(parent)
    , m_showAscii(true)
    , m_showOffset(true)
    , m_bytesPerLine(16)
    , m_currentSearchIndex(-1)
    , m_lastSearchCaseSensitive(false)
{
    setupUI();
    setupConnections();
}

HexViewer::~HexViewer()
{
}

void HexViewer::setupUI()
{
    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    
    // Control panel
    QHBoxLayout *controlLayout = new QHBoxLayout();
    
    // Offset control
    QLabel *offsetLabel = new QLabel(LANG("UI/hex_go_to_offset"), this);
    m_offsetSpinBox = new QSpinBox(this);
    m_offsetSpinBox->setRange(0, 0);
    m_offsetSpinBox->setPrefix(LANG("UI/hex_prefix"));
    m_offsetSpinBox->setDisplayIntegerBase(16);
    m_offsetSpinBox->setMaximumWidth(120);
    
    // Bytes per line control
    QLabel *bytesLabel = new QLabel(LANG("UI/hex_bytes_per_line"), this);
    m_bytesPerLineSpinBox = new QSpinBox(this);
    m_bytesPerLineSpinBox->setRange(8, 64);
    m_bytesPerLineSpinBox->setValue(16);
    m_bytesPerLineSpinBox->setMaximumWidth(80);
    
    // Display options
    m_showOffsetButton = new QPushButton(LANG("UI/hex_show_offset"), this);
    m_showOffsetButton->setCheckable(true);
    m_showOffsetButton->setChecked(true);
    
    m_showAsciiButton = new QPushButton(LANG("UI/hex_show_ascii"), this);
    m_showAsciiButton->setCheckable(true);
    m_showAsciiButton->setChecked(true);
    
    // Action buttons
    m_copyButton = new QPushButton(LANG("UI/button_copy_hex"), this);
    m_copyButton->setIcon(QIcon(":/images/imgs/copy.png"));
    m_findButton = new QPushButton(LANG("UI/button_find"), this);
    m_findButton->setIcon(QIcon(":/images/imgs/search.png"));
    
    // Search navigation buttons (initially disabled)
    m_findNextButton = new QPushButton("↓", this);
    m_findNextButton->setToolTip(LANG("UI/hex_search_find_next"));
    m_findNextButton->setMaximumWidth(30);
    m_findNextButton->setEnabled(false);
    
    m_findPrevButton = new QPushButton("↑", this);
    m_findPrevButton->setToolTip(LANG("UI/hex_search_find_previous"));
    m_findPrevButton->setMaximumWidth(30);
    m_findPrevButton->setEnabled(false);
    
    controlLayout->addWidget(offsetLabel);
    controlLayout->addWidget(m_offsetSpinBox);
    controlLayout->addWidget(bytesLabel);
    controlLayout->addWidget(m_bytesPerLineSpinBox);
    controlLayout->addStretch();
    controlLayout->addWidget(m_showOffsetButton);
    controlLayout->addWidget(m_showAsciiButton);
    controlLayout->addWidget(m_copyButton);
    controlLayout->addWidget(m_findButton);
    controlLayout->addWidget(m_findPrevButton);
    controlLayout->addWidget(m_findNextButton);
    
    mainLayout->addLayout(controlLayout);
    
    // Hex display
    m_hexText = new QTextEdit(this);
    m_hexText->setFontFamily(LANG("UI/font_consolas"));
    m_hexText->setFontPointSize(9);
    m_hexText->setReadOnly(true);
    m_hexText->setLineWrapMode(QTextEdit::NoWrap);
    m_hexText->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    m_hexText->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    
    mainLayout->addWidget(m_hexText);
    
    // Status bar
    QHBoxLayout *statusLayout = new QHBoxLayout();
    QLabel *statusLabel = new QLabel(LANG("UI/status_ready"), this);
    statusLayout->addWidget(statusLabel);
    statusLayout->addStretch();
    
    mainLayout->addLayout(statusLayout);
}

void HexViewer::setupConnections()
{
    connect(m_offsetSpinBox, QOverload<int>::of(&QSpinBox::valueChanged),
            this, &HexViewer::onOffsetChanged);
    connect(m_bytesPerLineSpinBox, QOverload<int>::of(&QSpinBox::valueChanged),
            this, &HexViewer::onBytesPerLineChanged);
    connect(m_showAsciiButton, &QPushButton::toggled,
            this, &HexViewer::onShowAsciiToggled);
    connect(m_showOffsetButton, &QPushButton::toggled,
            this, &HexViewer::onShowOffsetToggled);
    connect(m_copyButton, &QPushButton::clicked,
            this, &HexViewer::onCopySelection);
    connect(m_findButton, &QPushButton::clicked,
            this, &HexViewer::onFindText);
    connect(m_findNextButton, &QPushButton::clicked,
            this, &HexViewer::findNext);
    connect(m_findPrevButton, &QPushButton::clicked,
            this, &HexViewer::findPrevious);
}

void HexViewer::setData(const QByteArray &data)
{
    m_data = data;
    m_offsetSpinBox->setRange(0, qMax(0, data.size() - 1));
    
    // Debug: Print data information
    qDebug() << "HexViewer::setData called with" << data.size() << "bytes";
    
    // Enable/disable controls based on data availability
    bool hasData = !data.isEmpty();
    m_findButton->setEnabled(hasData);
    m_offsetSpinBox->setEnabled(hasData);
    m_bytesPerLineSpinBox->setEnabled(hasData);
    m_showOffsetButton->setEnabled(hasData);
    m_showAsciiButton->setEnabled(hasData);
    m_copyButton->setEnabled(hasData);
    
    // Clear search results when new data is loaded
    clearSearchResults();
    
    updateDisplay();
}

void HexViewer::clear()
{
    m_data.clear();
    m_hexText->clear();
    m_offsetSpinBox->setRange(0, 0);
    clearSearchResults();
}

void HexViewer::goToOffset(qint64 offset)
{
    if (offset >= 0 && offset < m_data.size()) {
        m_offsetSpinBox->setValue(static_cast<int>(offset));
        
        // Calculate which line contains this offset
        qint64 targetLine = offset / m_bytesPerLine;
        
        // Calculate the character position in the text for this line
        qint64 lineStartInText = 0;
        
        // Count characters in previous lines
        for (qint64 prevLine = 0; prevLine < targetLine; ++prevLine) {
            qint64 lineLength = 0;
            if (m_showOffset) lineLength += 10; // "00000000  " format
            lineLength += m_bytesPerLine * 3; // Two hex chars + space per byte
            if (m_showAscii) lineLength += 2 + m_bytesPerLine; // "  " + ascii chars
            lineLength += 1; // newline
            lineStartInText += lineLength;
        }
        
        // Calculate the character position for the specific offset within the line
        qint64 offsetInLine = offset % m_bytesPerLine;
        qint64 hexStartPos = lineStartInText + (m_showOffset ? 10 : 0);
        qint64 targetCharPos = hexStartPos + (offsetInLine * 3); // 3 chars per byte (XX )
        
        // Set cursor position and ensure it's visible
        QTextCursor cursor = m_hexText->textCursor();
        cursor.setPosition(static_cast<int>(targetCharPos));
        m_hexText->setTextCursor(cursor);
        m_hexText->ensureCursorVisible();
        
        // Highlight the specific byte
        highlightOffset(offset);
    }
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
    updateDisplay();
}

void HexViewer::setShowOffset(bool show)
{
    m_showOffset = show;
    m_showOffsetButton->setChecked(show);
    updateDisplay();
}

void HexViewer::updateDisplay()
{
    if (m_data.isEmpty()) {
        m_hexText->clear();
        return;
    }
    
    renderHexData();
}

void HexViewer::renderHexData()
{
    m_hexText->clear();
    
    QTextCursor cursor = m_hexText->textCursor();
    QTextCharFormat normalFormat = cursor.charFormat();
    QTextCharFormat offsetFormat = normalFormat;
    offsetFormat.setForeground(Qt::blue);
    offsetFormat.setFontWeight(QFont::Bold);
    
    QString hexContent;
    
    for (qint64 offset = 0; offset < m_data.size(); offset += m_bytesPerLine) {
        QByteArray lineData = getLineData(offset, m_bytesPerLine);
        
        QString line;
        
        // Offset
        if (m_showOffset) {
            line += formatOffset(offset);
            line += "  ";
        }
        
        // Hex data
        line += formatHexLine(lineData, offset);
        
        // ASCII representation
        if (m_showAscii) {
            line += "  ";
            line += formatAsciiLine(lineData);
        }
        
        hexContent += line + "\n";
    }
    
    m_hexText->setPlainText(hexContent);
    
    // Apply highlights
    applyHighlights();
}

QString HexViewer::formatHexLine(const QByteArray &lineData, qint64 offset)
{
    QString hexLine;
    
    for (int i = 0; i < m_bytesPerLine; ++i) {
        if (i < lineData.size()) {
            quint8 byte = static_cast<quint8>(lineData[i]);
            hexLine += QString("%1 ").arg(byte, 2, 16, QChar('0')).toUpper();
        } else {
            hexLine += "   "; // Padding for incomplete lines
        }
        
        // Add extra space every 8 bytes for readability
        if ((i + 1) % 8 == 0 && i < m_bytesPerLine - 1) {
            hexLine += " ";
        }
    }
    
    return hexLine;
}

QString HexViewer::formatAsciiLine(const QByteArray &lineData)
{
    QString asciiLine;
    
    for (int i = 0; i < m_bytesPerLine; ++i) {
        if (i < lineData.size()) {
            char c = lineData[i];
            if (c >= 32 && c <= 126) {
                asciiLine += c;
            } else {
                asciiLine += "."; // Non-printable character
            }
        } else {
            asciiLine += " "; // Padding
        }
    }
    
    return asciiLine;
}

QString HexViewer::formatOffset(qint64 offset)
{
    return QString("%1").arg(offset, 8, 16, QChar('0')).toUpper();
}

QByteArray HexViewer::getLineData(qint64 offset, int maxBytes)
{
    int remainingBytes = m_data.size() - offset;
    int bytesToRead = qMin(maxBytes, remainingBytes);
    
    if (bytesToRead <= 0) {
        return QByteArray();
    }
    
    return m_data.mid(offset, bytesToRead);
}

void HexViewer::highlightOffset(qint64 offset)
{
    if (m_data.isEmpty()) return;
    
    // Calculate line number
    int lineNumber = offset / m_bytesPerLine;
    
    // Get the text cursor and move to the line
    QTextCursor cursor = m_hexText->textCursor();
    cursor.movePosition(QTextCursor::Start);
    cursor.movePosition(QTextCursor::Down, QTextCursor::MoveAnchor, lineNumber);
    
    // Select the entire line
    cursor.movePosition(QTextCursor::StartOfLine);
    cursor.movePosition(QTextCursor::EndOfLine, QTextCursor::KeepAnchor);
    
    // Highlight the line
    QTextCharFormat highlightFormat;
    highlightFormat.setBackground(Qt::yellow);
    cursor.mergeCharFormat(highlightFormat);
    
    // Set cursor position and ensure visibility
    m_hexText->setTextCursor(cursor);
    m_hexText->ensureCursorVisible();
}

// Private slots
void HexViewer::onOffsetChanged(int value)
{
    goToOffset(value);
}

void HexViewer::onBytesPerLineChanged(int value)
{
    m_bytesPerLine = value;
    updateDisplay();
}

void HexViewer::onShowAsciiToggled(bool checked)
{
    m_showAscii = checked;
    updateDisplay();
}

void HexViewer::onShowOffsetToggled(bool checked)
{
    m_showOffset = checked;
    updateDisplay();
}

void HexViewer::onCopySelection()
{
    QTextCursor cursor = m_hexText->textCursor();
    if (cursor.hasSelection()) {
        QString selectedText = cursor.selectedText();
        QApplication::clipboard()->setText(selectedText);
    } else {
        // Copy all content if nothing is selected
        QApplication::clipboard()->setText(m_hexText->toPlainText());
    }
}

void HexViewer::onFindText()
{
    // Create a custom search dialog for better hex search experience
    QDialog searchDialog(this);
    searchDialog.setWindowTitle(LANG("UI/hex_find_text"));
    searchDialog.setModal(true);
    searchDialog.resize(400, 200);
    
    QVBoxLayout *mainLayout = new QVBoxLayout(&searchDialog);
    
    // Search pattern input
    QHBoxLayout *patternLayout = new QHBoxLayout();
    QLabel *patternLabel = new QLabel(LANG("UI/hex_search_pattern"), &searchDialog);
    QLineEdit *patternEdit = new QLineEdit(&searchDialog);
    patternEdit->setPlaceholderText(LANG("UI/hex_search_placeholder"));
    patternEdit->setMinimumWidth(250);
    patternLayout->addWidget(patternLabel);
    patternLayout->addWidget(patternEdit);
    
    // Search options
    QHBoxLayout *optionsLayout = new QHBoxLayout();
    QCheckBox *caseSensitiveCheck = new QCheckBox(LANG("UI/hex_search_case_sensitive"), &searchDialog);
    QCheckBox *hexOnlyCheck = new QCheckBox(LANG("UI/hex_search_hex_only"), &searchDialog);
    hexOnlyCheck->setChecked(true);
    optionsLayout->addWidget(caseSensitiveCheck);
    optionsLayout->addWidget(hexOnlyCheck);
    
    // Buttons
    QHBoxLayout *buttonLayout = new QHBoxLayout();
    QPushButton *findButton = new QPushButton(LANG("UI/hex_search_find"), &searchDialog);
    QPushButton *cancelButton = new QPushButton(LANG("UI/hex_search_cancel"), &searchDialog);
    findButton->setDefault(true);
    buttonLayout->addWidget(findButton);
    buttonLayout->addWidget(cancelButton);
    
    // Add layouts to main layout
    mainLayout->addLayout(patternLayout);
    mainLayout->addLayout(optionsLayout);
    mainLayout->addLayout(buttonLayout);
    
    // Connect signals
    connect(findButton, &QPushButton::clicked, &searchDialog, &QDialog::accept);
    connect(cancelButton, &QPushButton::clicked, &searchDialog, &QDialog::reject);
    
    // Focus on pattern input
    patternEdit->setFocus();
    
    if (searchDialog.exec() == QDialog::Accepted) {
        QString pattern = patternEdit->text().trimmed();
        if (!pattern.isEmpty()) {
            bool caseSensitive = caseSensitiveCheck->isChecked();
            bool hexOnly = hexOnlyCheck->isChecked();
            
            // Process the pattern based on options
            if (hexOnly) {
                // Remove spaces and common separators
                pattern = pattern.simplified().remove(' ');
            }
            
            // Perform the search
            findHexPattern(pattern, caseSensitive);
        }
    }
}

void HexViewer::highlightRange(quint32 startOffset, quint32 length, const QColor &color)
{
    if (m_data.isEmpty() || startOffset >= m_data.size()) return;
    
    // Clear previous highlights first
    clearHighlights();
    
    // Add highlight to the list with improved color
    HighlightRange highlight;
    highlight.startOffset = startOffset;
    highlight.length = qMin(length, static_cast<quint32>(m_data.size() - startOffset));
    
    // Use a more visible color if the provided color is too transparent
    QColor highlightColor = color;
    if (highlightColor.alpha() < 150) {
        highlightColor.setAlpha(200); // Make it more opaque
    }
    highlight.color = highlightColor;
    
    m_highlights.append(highlight);
    
    // Apply highlights to the existing content
    applyHighlights();
    
    // Ensure the highlighted area is visible
    goToOffset(startOffset);
}

void HexViewer::clearHighlights()
{
    m_highlights.clear();
    // Don't call updateDisplay() as it clears the content
    // Just clear the highlights and force a repaint
    if (m_hexText) {
        // Clear any existing formatting
        QTextCursor cursor = m_hexText->textCursor();
        cursor.select(QTextCursor::Document);
        QTextCharFormat normalFormat;
        normalFormat.setBackground(Qt::transparent);
        normalFormat.setForeground(Qt::black);
        normalFormat.setFontWeight(QFont::Normal);
        cursor.mergeCharFormat(normalFormat);
        
        // Force repaint
        m_hexText->viewport()->update();
    }
}

void HexViewer::applyHighlights()
{
    if (m_highlights.isEmpty()) return;
    
    QTextCursor cursor = m_hexText->textCursor();
    QString content = m_hexText->toPlainText();
    
    // Safety check - ensure we have content to highlight
    if (content.isEmpty()) return;
    
    // Debug: Print highlight information
    qDebug() << "Applying highlights:" << m_highlights.size() << "highlight(s)";
    for (const HighlightRange &highlight : m_highlights) {
        qDebug() << "Highlight: offset" << highlight.startOffset << "length" << highlight.length;
    }
    
    for (const HighlightRange &highlight : m_highlights) {
        // Calculate which lines this highlight spans
        qint64 startLine = highlight.startOffset / m_bytesPerLine;
        qint64 endLine = (highlight.startOffset + highlight.length - 1) / m_bytesPerLine;
        
        for (qint64 line = startLine; line <= endLine; ++line) {
            // Find the line in the text
            QStringList lines = content.split('\n');
            if (line >= lines.size()) continue;
            
            QString currentLine = lines[line];
            qint64 lineStartOffset = line * m_bytesPerLine;
            
            // Calculate highlight positions within this line
            qint64 highlightStartInLine = qMax(static_cast<qint64>(highlight.startOffset), lineStartOffset);
            qint64 highlightEndInLine = qMin(static_cast<qint64>(highlight.startOffset + highlight.length), lineStartOffset + m_bytesPerLine);
            
            if (highlightStartInLine < highlightEndInLine) {
                // Calculate character positions for the hex portion
                qint64 offsetInLine = highlightStartInLine - lineStartOffset;
                qint64 lengthInLine = highlightEndInLine - highlightStartInLine;
                
                // Position after offset display (if enabled)
                qint64 hexStartPos = m_showOffset ? 10 : 0; // "00000000  " format
                qint64 charStart = hexStartPos + (offsetInLine * 3); // 3 chars per byte (XX )
                qint64 charEnd = charStart + (lengthInLine * 3) - 1; // Don't include trailing space
                
                // Ensure we don't exceed line bounds
                if (charStart < currentLine.length() && charEnd < currentLine.length()) {
                    // Calculate absolute position in the entire text
                    qint64 absoluteStart = 0;
                    for (qint64 i = 0; i < line; ++i) {
                        absoluteStart += lines[i].length() + 1; // +1 for newline
                    }
                    absoluteStart += charStart;
                    
                    qint64 absoluteEnd = absoluteStart + (charEnd - charStart + 1);
                    
                    // Apply highlight to hex portion
                    cursor.setPosition(static_cast<int>(absoluteStart));
                    cursor.setPosition(static_cast<int>(absoluteEnd), QTextCursor::KeepAnchor);
                    
                    QTextCharFormat highlightFormat;
                    highlightFormat.setBackground(highlight.color);
                    highlightFormat.setForeground(QColor(0, 0, 0)); // Black text for better contrast
                    highlightFormat.setFontWeight(QFont::Bold); // Make highlighted text bold
                    cursor.mergeCharFormat(highlightFormat);
                    
                    // Also highlight the ASCII portion if enabled
                    if (m_showAscii) {
                        // Calculate ASCII position (after hex portion + separator)
                        qint64 asciiStartPos = hexStartPos + (m_bytesPerLine * 3) + 2; // +2 for "  " separator
                        qint64 asciiCharStart = asciiStartPos + offsetInLine;
                        qint64 asciiCharEnd = asciiCharStart + lengthInLine - 1;
                        
                        if (asciiCharStart < currentLine.length() && asciiCharEnd < currentLine.length()) {
                            // Calculate absolute position for ASCII
                            qint64 asciiAbsoluteStart = 0;
                            for (qint64 i = 0; i < line; ++i) {
                                asciiAbsoluteStart += lines[i].length() + 1; // +1 for newline
                            }
                            asciiAbsoluteStart += asciiCharStart;
                            
                            qint64 asciiAbsoluteEnd = asciiAbsoluteStart + (asciiCharEnd - asciiCharStart + 1);
                            
                            // Apply highlight to ASCII portion
                            cursor.setPosition(static_cast<int>(asciiAbsoluteStart));
                            cursor.setPosition(static_cast<int>(asciiAbsoluteEnd), QTextCursor::KeepAnchor);
                            cursor.mergeCharFormat(highlightFormat);
                        }
                    }
                }
            }
        }
    }
    
    // Restore cursor position
    m_hexText->setTextCursor(cursor);
}

// ============================================================================
// Enhanced Hexadecimal Search Implementation
// ============================================================================

void HexViewer::findHexPattern(const QString &pattern, bool caseSensitive)
{
    if (m_data.isEmpty() || pattern.isEmpty()) return;
    
    // Parse the hex pattern
    QByteArray hexPattern = parseHexPattern(pattern);
    if (hexPattern.isEmpty()) {
        QMessageBox::warning(this, LANG("UI/hex_search_invalid_pattern"), 
            LANG("UI/hex_search_invalid_message"));
        return;
    }
    
    // Store search parameters
    m_lastSearchPattern = hexPattern;
    m_lastSearchCaseSensitive = caseSensitive;
    
    // Find all occurrences
    m_searchResults = findPatternInData(hexPattern, caseSensitive);
    m_currentSearchIndex = -1;
    
    if (m_searchResults.isEmpty()) {
        QMessageBox::information(this, LANG("UI/hex_search_no_results"), 
            LANG_PARAM("UI/hex_search_no_matches", "pattern", pattern));
        clearSearchResults();
        return;
    }
    
    // Show results count
    QMap<QString, QString> params;
    params["count"] = QString::number(m_searchResults.size());
    params["pattern"] = pattern;
    QMessageBox::information(this, LANG("UI/hex_search_no_results"), 
        LANG_PARAMS("UI/hex_search_results_found", params));
    
    // Enable navigation buttons
    m_findNextButton->setEnabled(true);
    m_findPrevButton->setEnabled(true);
    
    // Highlight all search results
    highlightSearchResults();
    
    // Go to first result
    if (!m_searchResults.isEmpty()) {
        goToSearchResult(0);
    }
}

QByteArray HexViewer::parseHexPattern(const QString &pattern)
{
    QString cleanPattern = pattern.trimmed();
    
    // Remove common prefixes and separators
    cleanPattern = cleanPattern.remove("0x", Qt::CaseInsensitive);
    cleanPattern = cleanPattern.remove("h", Qt::CaseInsensitive);
    cleanPattern = cleanPattern.remove("\\x");
    cleanPattern = cleanPattern.remove(" ");
    cleanPattern = cleanPattern.remove("\t");
    cleanPattern = cleanPattern.remove(",");
    cleanPattern = cleanPattern.remove(";");
    
    // Validate hex pattern
    if (cleanPattern.isEmpty() || cleanPattern.length() % 2 != 0) {
        return QByteArray();
    }
    
    // Convert to byte array
    QByteArray result;
    for (int i = 0; i < cleanPattern.length(); i += 2) {
        QString byteStr = cleanPattern.mid(i, 2);
        bool ok;
        char byte = static_cast<char>(byteStr.toInt(&ok, 16));
        if (!ok) {
            return QByteArray(); // Invalid hex
        }
        result.append(byte);
    }
    
    return result;
}

QList<HexViewer::SearchResult> HexViewer::findPatternInData(const QByteArray &pattern, bool caseSensitive)
{
    QList<SearchResult> results;
    if (pattern.isEmpty() || m_data.isEmpty()) return results;
    
    QByteArray searchData = m_data;
    QByteArray searchPattern = pattern;
    
    if (!caseSensitive) {
        searchData = searchData.toLower();
        searchPattern = searchPattern.toLower();
    }
    
    int offset = 0;
    while (true) {
        int index = searchData.indexOf(searchPattern, offset);
        if (index == -1) break;
        
        SearchResult result;
        result.offset = index;
        result.length = pattern.size();
        result.pattern = pattern;
        results.append(result);
        
        offset = index + 1; // Continue searching from next position
    }
    
    return results;
}

void HexViewer::findNext()
{
    if (m_searchResults.isEmpty()) return;
    
    m_currentSearchIndex = (m_currentSearchIndex + 1) % m_searchResults.size();
    goToSearchResult(m_currentSearchIndex);
}

void HexViewer::findPrevious()
{
    if (m_searchResults.isEmpty()) return;
    
    m_currentSearchIndex = (m_currentSearchIndex - 1 + m_searchResults.size()) % m_searchResults.size();
    goToSearchResult(m_currentSearchIndex);
}

void HexViewer::clearSearchResults()
{
    m_searchResults.clear();
    m_currentSearchIndex = -1;
    m_lastSearchPattern.clear();
    
    // Disable navigation buttons
    m_findNextButton->setEnabled(false);
    m_findPrevButton->setEnabled(false);
    
    // Clear search highlights
    clearHighlights();
}

void HexViewer::highlightSearchResults()
{
    if (m_searchResults.isEmpty()) return;
    
    // Clear previous highlights
    clearHighlights();
    
    // Add highlights for all search results
    for (const SearchResult &result : m_searchResults) {
        QColor searchColor(255, 0, 255, 150); // Magenta with transparency
        highlightRange(static_cast<quint32>(result.offset), 
                      static_cast<quint32>(result.length), 
                      searchColor);
    }
}

void HexViewer::goToSearchResult(int index)
{
    if (index < 0 || index >= m_searchResults.size()) return;
    
    const SearchResult &result = m_searchResults[index];
    m_currentSearchIndex = index;
    
    // Go to the offset
    goToOffset(result.offset);
    
    // Update status
    QMap<QString, QString> params;
    params["current"] = QString::number(index + 1);
    params["total"] = QString::number(m_searchResults.size());
    params["offset"] = QString::number(result.offset, 16);
    QString status = LANG_PARAMS("UI/hex_search_result_status", params);
    
    // Find status label and update it
    QList<QLabel*> labels = findChildren<QLabel*>();
    for (QLabel *label : labels) {
        if (label->text().contains(LANG("UI/status_ready_contains")) || label->text().contains(LANG("UI/status_pronto_contains"))) {
            label->setText(status);
            break;
        }
    }
}
