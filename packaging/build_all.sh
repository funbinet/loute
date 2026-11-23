#!/bin/bash
# LOUTE Master Build Script
# This script executes all packaging scripts to generate the APK, DEB, and EXE.

set -e

echo "=========================================="
echo "    Initiating LOUTE Multi-Platform Build  "
echo "=========================================="

cd "$(dirname "$0")"

if [ -f "build_android_apk.sh" ]; then
    ./build_android_apk.sh
else
    echo "[!] build_android_apk.sh not found."
fi

if [ -f "build_linux_deb.sh" ]; then
    ./build_linux_deb.sh
else
    echo "[!] build_linux_deb.sh not found."
fi

if [ -f "build_windows_exe.sh" ]; then
    ./build_windows_exe.sh
else
    echo "[!] build_windows_exe.sh not found."
fi

if [ -f "build_arch.sh" ]; then
    ./build_arch.sh
else
    echo "[!] build_arch.sh not found."
fi

echo "=========================================="
echo "    Multi-Platform Build Complete!        "
echo "=========================================="
