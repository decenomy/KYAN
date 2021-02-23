#!/bin/bash
echo -e "\033[0;32mHow many CPU cores do you want to be used in compiling process? (Default is 1. Press enter for default.)\033[0m"
read -e CPU_CORES
if [ -z "$CPU_CORES" ]
then
	CPU_CORES=1
fi

# Upgrade the system and install required dependencies
	sudo apt update
	sudo apt install git zip unzip build-essential libtool bsdmainutils autotools-dev autoconf pkg-config automake python3 cmake curl g++-mingw-w64-x86-64 -y
	# Required to enable C++ threading libraries (e.g. std::thread)
    sudo update-alternatives --set x86_64-w64-mingw32-g++  /usr/bin/x86_64-w64-mingw32-g++-posix
    sudo update-alternatives --set x86_64-w64-mingw32-gcc  /usr/bin/x86_64-w64-mingw32-gcc-posix

# Clone KYAN code from KYAN official Github repository
	git clone https://github.com/kyancoin/KYAN

# Entering KYAN directory
	cd KYAN

# Compile dependencies
	cd depends
	make -j$(echo $CPU_CORES) HOST=x86_64-w64-mingw32 
	cd ..

# Compile KYAN
	./autogen.sh
	./configure --prefix=$(pwd)/depends/x86_64-w64-mingw32 --disable-debug --disable-tests --disable-bench CFLAGS="-O3" CXXFLAGS="-O3"
	make -j$(echo $CPU_CORES) HOST=x86_64-w64-mingw32
	cd ..

# Create zip file of binaries
	cp KYAN/src/kyand.exe KYAN/src/kyan-cli.exe KYAN/src/kyan-tx.exe KYAN/src/qt/kyan-qt.exe .
	zip KYAN-Windows.zip kyand.exe kyan-cli.exe kyan-tx.exe kyan-qt.exe
	rm -f kyand.exe kyan-cli.exe kyan-tx.exe kyan-qt.exe
