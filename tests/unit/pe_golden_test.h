#ifndef PE_GOLDEN_TEST_H
#define PE_GOLDEN_TEST_H

#include <QObject>

class PEGoldenTest : public QObject
{
    Q_OBJECT

private slots:
    void minimalPe64_parsesAndProducesFindings();
    void entryPointDisasmRecognizesPrologue();
};

#endif // PE_GOLDEN_TEST_H
