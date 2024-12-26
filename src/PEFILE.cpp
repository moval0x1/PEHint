/*

    Header from: https://github.com/0xRick/PE-Parser/blob/main/PE-Parser/PEFILE.cpp

*/

#include "PEFILE.h"

// INITIAL PARSE //

int INITPARSE(QFile &PpeFile) {

    ___IMAGE_DOS_HEADER TMP_DOS_HEADER;
    WORD PEFILE_TYPE;

    // ::fseek(PpeFile, 0, SEEK_SET);
    // ::fread(&TMP_DOS_HEADER, sizeof(___IMAGE_DOS_HEADER), 1, PpeFile);

    // Seek to the beginning of the file
    if (!PpeFile.seek(0)) {
        QMessageBox::critical(nullptr, "File Error", "Failed to seek to the start of the file.");
        return -1;
    }

    // Read the IMAGE_DOS_HEADER structure
    if (PpeFile.read(reinterpret_cast<char*>(&TMP_DOS_HEADER), sizeof(___IMAGE_DOS_HEADER)) != sizeof(___IMAGE_DOS_HEADER)) {
        QMessageBox::critical(nullptr, "File Error", "Failed to read IMAGE_DOS_HEADER from the file.");
        return -1;
    }

    if (TMP_DOS_HEADER.e_magic != ___IMAGE_DOS_SIGNATURE) {
        printf("Error. Not a PE file.\n");
        return 1;
    }

    // ::fseek(PpeFile, (TMP_DOS_HEADER.e_lfanew + sizeof(DWORD) + sizeof(___IMAGE_FILE_HEADER)), SEEK_SET);
    // ::fread(&PEFILE_TYPE, sizeof(WORD), 1, PpeFile);

    // Calculate the seek position
    qint64 seekPosition = TMP_DOS_HEADER.e_lfanew + sizeof(quint32) + sizeof(___IMAGE_FILE_HEADER); // DWORD equivalent is quint32

    // Seek to the calculated position
    if (!PpeFile.seek(seekPosition)) {
        QMessageBox::critical(nullptr, "File Error", QString("Failed to seek to position: %1").arg(seekPosition));
        return -1;
    }

    // Read the PEFILE_TYPE (WORD equivalent)
    if (PpeFile.read(reinterpret_cast<char*>(&PEFILE_TYPE), sizeof(quint16)) != sizeof(quint16)) {
        QMessageBox::critical(nullptr, "File Error", QString("Failed to read PEFILE_TYPE at position: %1").arg(seekPosition));
        return -1;
    }

    if (PEFILE_TYPE == ___IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        return 32;
    }
    else if (PEFILE_TYPE == ___IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        return 64;
    }
    else {
        printf("Error while parsing IMAGE_OPTIONAL_HEADER.Magic. Unknown Type.\n");
        return 1;
    }

}
