#!/bin/bash

set -e

# Detect operating system/package manager
if command -v apt-get &>/dev/null; then
    PKG_MANAGER="apt"
elif command -v dnf &>/dev/null; then
    PKG_MANAGER="dnf"
elif command -v yum &>/dev/null; then
    PKG_MANAGER="yum"
elif command -v pacman &>/dev/null; then
    PKG_MANAGER="pacman"
elif command -v brew &>/dev/null; then
    PKG_MANAGER="brew"
else
    echo "Unsupported package manager."
    exit 1
fi

install_package() {
    case $PKG_MANAGER in
        apt)
            sudo apt-get update
            sudo apt-get install -y "$@"
            ;;
        dnf)
            sudo dnf install -y "$@"
            ;;
        yum)
            sudo yum install -y "$@"
            ;;
        pacman)
            sudo pacman -Sy --noconfirm "$@"
            ;;
        brew)
            brew install "$@"
            ;;
    esac
}

echo "Checking for g++..."
if ! command -v g++ &>/dev/null; then
    echo "g++ not found. Installing..."
    case $PKG_MANAGER in
        apt) install_package g++ ;;
        dnf|yum) install_package gcc-c++ ;;
        pacman) install_package gcc ;;
        brew) install_package gcc ;;
    esac
else
    echo "g++ is already installed."
fi

echo "Checking for OpenSSL..."
if ! command -v openssl &>/dev/null; then
    echo "OpenSSL not found. Installing..."
    case $PKG_MANAGER in
        apt) install_package openssl libssl-dev ;;
        dnf|yum) install_package openssl openssl-devel ;;
        pacman) install_package openssl ;;
        brew) install_package openssl ;;
    esac
else
    echo "OpenSSL is already installed."
fi

echo "Checking for SQLite3..."
if ! command -v sqlite3 &>/dev/null; then
    echo "SQLite3 not found. Installing..."
    case $PKG_MANAGER in
        apt) install_package sqlite3 libsqlite3-dev ;;
        dnf|yum) install_package sqlite sqlite-devel ;;
        pacman) install_package sqlite ;;
        brew) install_package sqlite ;;
    esac
else
    echo "SQLite3 is already installed."
fi

echo "All dependencies are installed."
echo "Building the Octra Vanity Address Generator"

g++ -std=c++20 -O3 -march=native ./octra_vanity_wallet.cpp \
    -o ./octra_vanity \
    -lssl -lcrypto -lsqlite3

echo "Done"
echo "Start the vanity:"
echo "./octra_vanity"
echo "Usage:"
echo "./octra_vanity --help"