#ifndef PE_UI_PRESENTER_H
#define PE_UI_PRESENTER_H

#include <QList>
#include <QString>

#include "pe_structures.h"

class QTreeWidgetItem;
class PEParserNew;

/**
 * Builds Structure-tab tree items from parsed PE data.
 * Keeps presentation logic out of PEParserNew and MainWindow.
 */
class PEUIPresenter
{
public:
    explicit PEUIPresenter(PEParserNew *parser);

    QList<QTreeWidgetItem *> buildStructureTree();

private:
    PEParserNew *m_parser;

    void addTreeField(QTreeWidgetItem *parent, const QString &name, const QString &value, quint32 offset,
                      quint32 size, const QString &jsonFieldKey = QString());
    void addDOSHeaderFields(QTreeWidgetItem *parent, const IMAGE_DOS_HEADER *dosHeader);
    void addPEHeaderFields(QTreeWidgetItem *parent, const IMAGE_FILE_HEADER *fileHeader);
    void addOptionalHeaderFields(QTreeWidgetItem *parent, const IMAGE_OPTIONAL_HEADER *optionalHeader);
    void addSectionFields(QTreeWidgetItem *parent);
    void addRichHeaderFields(QTreeWidgetItem *parent, quint32 richOffset);
    void addDataDirectoryFields(QTreeWidgetItem *parent);
    void appendExceptionDirectoryDetailTree(QTreeWidgetItem *dirItem, quint32 rva, quint32 regionSize);
    void appendCertificateDirectoryDetailTree(QTreeWidgetItem *dirItem, quint32 filePointer, quint32 regionSize);
    void appendTLSDirectoryDetailTree(QTreeWidgetItem *dirItem, quint32 rva, quint32 regionSize);
    void appendLoadConfigDirectoryDetailTree(QTreeWidgetItem *dirItem, quint32 rva, quint32 regionSize);
    void appendResourceDirectoryDetailTree(QTreeWidgetItem *dirItem, quint32 rva, quint32 regionSize);
    void appendComDescriptorDetailTree(QTreeWidgetItem *dirItem, quint32 rva, quint32 regionSize);
};

#endif // PE_UI_PRESENTER_H
