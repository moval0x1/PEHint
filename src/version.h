#ifndef VERSION_H
#define VERSION_H

// Version information - update this single file for all version changes
#define PEHINT_VERSION_MAJOR 0
#define PEHINT_VERSION_MINOR 3
#define PEHINT_VERSION_PATCH 1

// String versions
#define PEHINT_VERSION_STRING "0.3.1"
#define PEHINT_VERSION_STRING_FULL "v0.3.1"

// Build information
#define PEHINT_BUILD_DATE __DATE__
#define PEHINT_BUILD_TIME __TIME__

// Version macros for conditional compilation
#define PEHINT_VERSION_CHECK(major, minor, patch) \
    (PEHINT_VERSION_MAJOR > major || \
     (PEHINT_VERSION_MAJOR == major && PEHINT_VERSION_MINOR > minor) || \
     (PEHINT_VERSION_MAJOR == major && PEHINT_VERSION_MINOR == minor && PEHINT_VERSION_PATCH >= patch))

// Helper macros
#define PEHINT_VERSION_AT_LEAST(major, minor, patch) PEHINT_VERSION_CHECK(major, minor, patch)
#define PEHINT_VERSION_EQUAL(major, minor, patch) \
    (PEHINT_VERSION_MAJOR == major && PEHINT_VERSION_MINOR == minor && PEHINT_VERSION_PATCH == patch)

#endif // VERSION_H
