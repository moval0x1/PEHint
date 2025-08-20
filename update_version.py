#!/usr/bin/env python3
"""
Version Update Script for PEHint
Updates version numbers in version.h and other files automatically
"""

import re
import sys
import argparse
from pathlib import Path

def update_version_header(version_file, major, minor, patch):
    """Update the version.h file with new version numbers"""
    content = version_file.read_text()
    
    # Update version numbers
    content = re.sub(r'#define PEHINT_VERSION_MAJOR \d+', f'#define PEHINT_VERSION_MAJOR {major}', content)
    content = re.sub(r'#define PEHINT_VERSION_MINOR \d+', f'#define PEHINT_VERSION_MINOR {minor}', content)
    content = re.sub(r'#define PEHINT_VERSION_PATCH \d+', f'#define PEHINT_VERSION_PATCH {patch}', content)
    
    # Update string versions
    content = re.sub(r'#define PEHINT_VERSION_STRING "\d+\.\d+\.\d+"', f'#define PEHINT_VERSION_STRING "{major}.{minor}.{patch}"', content)
    content = re.sub(r'#define PEHINT_VERSION_STRING_FULL "v\d+\.\d+\.\d+"', f'#define PEHINT_VERSION_STRING_FULL "v{major}.{minor}.{patch}"', content)
    
    version_file.write_text(content)
    print(f"Updated {version_file} to version {major}.{minor}.{patch}")

def update_cmake_version(cmake_file, major, minor, patch):
    """Update CMakeLists.txt version if it has hardcoded version"""
    content = cmake_file.read_text()
    
    # Check if there's a hardcoded version to update
    if f'VERSION {major}.{minor}.{patch}' in content:
        print(f"CMakeLists.txt already has correct version {major}.{minor}.{patch}")
        return
    
    # Look for hardcoded version pattern
    pattern = r'project\(PEHint VERSION \d+\.\d+\.\d+'
    if re.search(pattern, content):
        content = re.sub(pattern, f'project(PEHint VERSION {major}.{minor}.{patch}', content)
        cmake_file.write_text(content)
        print(f"Updated {cmake_file} to version {major}.{minor}.{patch}")
    else:
        print(f"No hardcoded version found in {cmake_file}")

def main():
    parser = argparse.ArgumentParser(description='Update PEHint version numbers')
    parser.add_argument('version', help='Version string (e.g., 0.4.2)')
    parser.add_argument('--dry-run', action='store_true', help='Show what would be changed without making changes')
    
    args = parser.parse_args()
    
    # Parse version string
    try:
        major, minor, patch = map(int, args.version.split('.'))
    except ValueError:
        print("Error: Version must be in format X.Y.Z (e.g., 0.4.2)")
        sys.exit(1)
    
    print(f"Updating PEHint to version {major}.{minor}.{patch}")
    
    # Get project root
    project_root = Path(__file__).parent
    version_file = project_root / 'src' / 'version.h'
    cmake_file = project_root / 'CMakeLists.txt'
    
    if not version_file.exists():
        print(f"Error: {version_file} not found")
        sys.exit(1)
    
    if args.dry_run:
        print("DRY RUN - No changes will be made")
        print(f"Would update {version_file} to version {major}.{minor}.{patch}")
        print(f"Would check {cmake_file} for hardcoded versions")
        return
    
    # Update files
    update_version_header(version_file, major, minor, patch)
    update_cmake_version(cmake_file, major, minor, patch)
    
    print(f"\nVersion updated successfully to {major}.{minor}.{patch}")
    print("Remember to rebuild the project for changes to take effect")

if __name__ == '__main__':
    main()
