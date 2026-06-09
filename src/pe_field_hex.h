#ifndef PE_FIELD_HEX_H
#define PE_FIELD_HEX_H

#include <QtGlobal>

struct PeFieldHexRange {
    quint32 offset = 0;
    quint32 size = 0;
    bool canHighlight = false;
    bool canGoTo = false;
};

#endif // PE_FIELD_HEX_H
