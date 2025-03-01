# bellatui
Cross platform console based bella render server/client

A command line bella renderer with encrypted networking with an interactive 
TUI ( text user interface )for uploading .bsz scenes, starting
render, downloading images. Additional commands allow viewing progress, stopping renders, etc

## Usage
The same executable can be started in either client or server mode

Client
```
bellatui

========= Bella Engine SDK (version: 24.6.0.0, build date: 1734912267) =========
bellazmq connecting to server...
connection successful
```
Server
```
bellatui -s
========= Bella Engine SDK (version: 24.6.0.0, build date: 1734912267) =========
Entered: Public Key Serving Mode
Client connected
```

<<<<<<< HEAD

## Build 


##MacOS
```
mkdir ~/homebrew
curl -L https://github.com/Homebrew/brew/tarball/master | tar xz --strip-components 1 -C ~/homebrew
eval "$(~/homebrew/bin/brew shellenv)"
brew update --force --quiet
chmod -R go-w "$(brew --prefix)/share/zsh"
curl -LO https://github.com/Kitware/CMake/releases/download/v3.31.6/cmake-3.31.6-macos-universal.dmg
open cmake-3.31.6-macos-universal.dmg 
brew install libsodium
brew install gnutls
brew install pkg-config
git clone https://github.com/zeromq/libzmq
cd libzmq
mkdir build
cd build
/Applications/CMake.app/Contents/bin/cmake .. -DENABLE_CURVE=ON -DWITH_LIBSODIUM=~/homebrew/Cellar/libsodium/1.0.20/include/sodium -DSODIUM_INCLUDE_DIRS=~/homebrew/Cellar/libsodium/1.0.20/include -DSODIUM_LIBRARIES=~/homebrew/Cellar/libsodium/1.0.20/lib/libsodium.a
make
cd ..
git clone https://github.com/zeromq/cppzmq
git clone https://github.com/oomer/bellatui.git
cd bellatui
makefile

```


##Linux
=======
# Build 

# Linux

### bella_engine_sdk
>>>>>>> 6760d2b (added msbuild file, detailed instructions to build on each platform, and arg support for port and address)
```
curl -O https://downloads.bellarender.com/bella_engine_sdk-24.6.0.tar.gz
tar -xvf bella_engine_sdk-24.6.0.tar.gz
```

### ubuntu tool needed
```
apt install -y build-essential
apt install -y libx11-dev
apt install  -y libgl1-mesa-dev
apt install -y libtool
apt install -y libsodium-dev
apt install -y cmake
apt install libgnutls28-dev 
apt install pkg-config 
```

### libzmq
```
git clone https://github.com/zeromq/libzmq
cd libzmq
mkdir build
cd build
cmake .. -DENABLE_CURVE=ON -DWITH_LIBSODIUM=/usr/include/sodium
make -j4
make install
```

### cppzmq
```
cd ../..
git clone https://github.com/zeromq/cppzmq
cd cppzmq
mkdir build
cd build
cmake .. 
<<<<<<< HEAD

g++ bellatui.cpp -o server -lzmq -Wl,-rpath,.
```

=======
```

### bellatui
```
cd ../..
git clone https://github.com/oomer/bellatui.git
cd bellatui
make
```

# Windows

vcpkg install boost:x64-windows boost:x86-windows zeromq[sodium]:x64-windows zeromq[sodium]:x86-windows

x64 Developer console
```
git clone https://github.com/oomer/bellatui.git
msbuild bellatui.vcxproj /p:Configuration=release /p:Platform=x64 /p:PlatformToolset=v143
```

# MacOS

Use this when homebrew commands are needed

    eval "$(~/homebrew/bin/brew shellenv)"

### Install homebrew without sudo
Run the eval to set dev variables and path
```
mkdir ~/homebrew
curl -L https://github.com/Homebrew/brew/tarball/master | tar xz --strip-components 1 -C ~/homebrew
eval "$(~/homebrew/bin/brew shellenv)"
brew update --force --quiet
chmod -R go-w "$(brew --prefix)/share/zsh"
```
### cmake , drag to Applications
```
curl -LO https://github.com/Kitware/CMake/releases/download/v3.31.6/cmake-3.31.6-macos-universal.dmg
open cmake-3.31.6-macos-universal.dmg 
```

### brew dependencies
```
brew install libsodium
brew install gnutls
brew install pkg-config
```

### compile libzmq
```
git clone https://github.com/zeromq/libzmq
cd libzmq
mkdir build
cd build
/Applications/CMake.app/Contents/bin/cmake .. -DENABLE_CURVE=ON -DWITH_LIBSODIUM=~/homebrew/Cellar/libsodium/1.0.20/include/sodium -DSODIUM_INCLUDE_DIRS=~/homebrew/Cellar/libsodium/1.0.20/include -DSODIUM_LIBRARIES=~/homebrew/Cellar/libsodium/1.0.20/lib/libsodium.a
make
cd ../..
```
### header only cppzmq
```
git clone https://github.com/zeromq/cppzmq
```
### bellatui
```
cd ../..
git clone https://github.com/oomer/bellatui.git
cd bellatui
make
```

# Notes
```
g++ -std=c++11 server.cpp -o server -I../libzmq/include -I../cppzmq -L../libzmq/build/lib -lzmq -Wl,-rpath,. 
g++ -std=c++11 server.cpp -o server -I../libzmq/include -I../cppzmq -L../libzmq/build/lib -lzmq -Wl,-rpath,. 
>>>>>>> 6760d2b (added msbuild file, detailed instructions to build on each platform, and arg support for port and address)

# Windows
```
cl /std:c++17 client.cpp -Fe:client.exe -Ic:\Users\cupcake\github\vcpkg\installed\x64-windows\include\ /link c:\Users\cupcake\github\vcpkg\installed\x64-windows\lib\libzmq-mt-4_3_5.lib

cl /std:c++17 server.cpp -Fe:server.exe -Ic:\Users\cupcake\github\vcpkg\installed\x64-windows\include\ /link c:\Users\cupcake\github\vcpkg\installed\x64-windows\lib\libzmq-mt-4_3_5.lib



clang++ -o bin/Darwin/client obj/Darwin/client.o -mmacosx-version-min=11.0 -isysroot /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk -framework Cocoa -framework IOKit -framework CoreVideo -framework CoreFoundation -framework Accelerate -fvisibility=hidden -O5 -rpath @executable_path -weak_library ./lib/libvulkan.dylib -L./lib -L../libzmq/build/lib -lbella_engine_sdk -lm -lzmq -ldl

```
<<<<<<< HEAD
=======



>>>>>>> 6760d2b (added msbuild file, detailed instructions to build on each platform, and arg support for port and address)
