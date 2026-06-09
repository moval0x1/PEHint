#ifndef PE_CLI_SCAN_H
#define PE_CLI_SCAN_H

/** True when argv requests headless findings scan (--scan). */
bool peCliScanRequested(int argc, char *argv[]);

/** Run CLI scan; returns process exit code (does not return -1). */
int runPeCliScan(int argc, char *argv[]);

#endif // PE_CLI_SCAN_H
