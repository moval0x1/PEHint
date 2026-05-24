#include "pe_golden_test.h"

#include "pe_parser_new.h"
#include "pe_findings.h"
#include "pe_ep_disasm.h"
#include "language_manager.h"
#include "helpers/minimal_pe_builder.h"

#include <QtTest>
#include <QTemporaryFile>

void PEGoldenTest::minimalPe64_parsesAndProducesFindings()
{
    LanguageManager::getInstance().initialize();
    LanguageManager::getInstance().setLanguage(QStringLiteral("en"));
    QVERIFY(PEFindingsEngine::loadRules());

    const QByteArray bytes = buildMinimalPe64();
    QTemporaryFile tempFile;
    tempFile.setAutoRemove(true);
    QVERIFY(tempFile.open());
    tempFile.write(bytes);
    tempFile.close();

    PEParserNew parser;
    QVERIFY(parser.loadFile(tempFile.fileName()));
    QVERIFY(parser.isValid());

    const PEDataModel &model = parser.getDataModel();
    QVERIFY(model.getFileMetrics().entryPointRva != 0);
    QVERIFY(!model.getFileMetrics().entryPointBytesHex.isEmpty());

    const auto rvaToFo = [&parser](quint32 rva) { return parser.rvaToFileOffset(rva); };
    const QVector<PEFindingInstance> findings = PEFindingsEngine::evaluate(model, rvaToFo);
    QVERIFY(!findings.isEmpty());
}

void PEGoldenTest::entryPointDisasmRecognizesPrologue()
{
    const QByteArray bytes = QByteArray::fromHex("4883EC28E805000000");
    const QStringList lines = PEEpDisasm::disassembleEntryPoint(true, bytes);
    QVERIFY(!lines.isEmpty());
    QVERIFY(lines.first().contains(QStringLiteral("sub rsp")));
}
