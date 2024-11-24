# PEHint

![PEHint](/imgs/PEHint.png)

A Portable Executable Hint that was created for study purposes.<br/>Feel free to use it and help improve. ;)

Here, I'm documenting my plans and the process of developing the tool.

## PE Hint Software Development Plan

### 1. **Planning and Design Phase**
   - [ ] **Define Key Features**:
     - [x] Parsing and displaying PE file structure (headers, sections, imports, exports, etc.).
     - [ ] Highlighting suspicious PE anomalies (like strange sections, invalid headers).
     - [ ] Integration with other tools or libraries (e.g., VirusTotal API for quick OSINT).
     - [ ] Optional: Provide an option to generate reports based on the PE analysis.
   - [ ] **Select Technology Stack**:
     - [x] C++ as the programming language.
     - [x] Use Qt as the GUI framework.
     - [x] Select or implement libraries for PE file parsing (consider `LIEF` or `pe-parse`, or write your own parser in C++).
   - [ ] **Design User Interface (UI)**:
     - [ ] Sketch the UI with essential features like file loading, structure display, and report generation.
     - [ ] Plan for advanced features like binary search, section extraction, and export list filtering.

### 2. **Implementation Phase**
   - [ ] **Set Up Development Environment**:
     - [x] Initialize the project using CMake for build management.
     - [ ] Configure Qt for UI design and PE parsing.
   - [ ] **Core PE Parser Development in C++**:
     - [ ] Implement DOS Header parsing.
     - [ ] Implement NT Headers parsing (File Header, Optional Header).
     - [ ] Parse Section Headers and display section attributes.
     - [ ] Parse Import Table and Export Table.
     - [ ] Implement parsing for Data Directories (Resources, Debug, etc.).
   - [ ] **PE Anomalies Detection**:
     - [ ] Implement checks for suspicious anomalies like unusual section sizes, missing headers, or obfuscated imports.
   - [ ] **UI Integration**:
     - [ ] Build basic UI in Qt to load and display PE structure.
     - [ ] Add interactive features: click on sections to expand details.
     - [ ] Provide file saving/export functionality for analysis reports.

### 3. **Advanced Features and Integration**
   - [ ] **Implement Hex Viewer**:
     - [ ] Add a hex view of the PE file to inspect raw data.
   - [ ] **Malware Analysis Focus**:
     - [ ] Add an option to flag common PE tricks used in malware (e.g., suspicious imports, packed sections).
     - [ ] Provide OSINT integration (like fetching details from online databases or VT).
   - [ ] **Plugin Support (Optional)**:
     - [ ] Create a plugin system that allows for additional analyzers (e.g., CAPA plugin for function identification).

### 4. **Testing and Debugging**
   - [ ] **Unit Testing**:
     - [ ] Test individual components like PE parsing and anomaly detection.
   - [ ] **UI Testing**:
     - [ ] Test file loading, interactions, and exporting functionality.
   - [ ] **Performance Optimization**:
     - [ ] Ensure the software handles large PE files efficiently without freezing.
   - [ ] **Cross-Platform Compatibility**:
     - [ ] Test the software on different Windows versions and ensure compatibility with various PE file versions.

### 5. **Documentation and Teaching Materials**
   - [ ] **Document PE Hint Software**:
     - [ ] Write detailed documentation on how to use the software.
     - [ ] Provide code comments to help others understand the codebase.
   - [ ] **Create Teaching Materials**:
     - [ ] Prepare slides or notes explaining the PE structure and the tool’s usage.
     - [ ] Create guided exercises or labs where students can use the tool to analyze PE files.

### 6. **Release**
   - [ ] **Prepare Beta Release**:
     - [ ] Share the first version with a selected group of users for feedback.
   - [ ] **Collect Feedback**:
     - [ ] Implement improvements based on the feedback from users.
   - [ ] **Final Release**:
     - [ ] Release the stable version along with documentation and teaching materials.

## References
- https://0xrick.github.io/win-internals/pe1/
- https://learn.microsoft.com/en-us/windows/win32/api/winnt/
- https://learn.microsoft.com/en-us/windows/win32/api/dbghelp/