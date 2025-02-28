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

## Build 

##Linux
```
apt install -y libzmq-dev
ldconfig
apt install -y libtool
apt install -y libsodium-dev
apt install -y cmake

git clone https://github.com:weak_library/zeromq/libzmq
apt install libgnutls28-dev 
apt install pkg-config 
cd libzmq
mkdir build
cd build
cmake .. -DENABLE_CURVE=ON -DWITH_LIBSODIUM=/usr/include/sodium


git https://github.com/zeromq/cppzmq
cd cppzmq
mkdir build
cd build
cmake .. 

g++ server.cpp -o server -lzmq -Wl,-rpath,.
```

##MacOS
```
g++ -std=c++11 server.cpp -o server -I../libzmq/include -I../cppzmq -L../libzmq/build/lib -lzmq -Wl,-rpath,. 
g++ -std=c++11 server.cpp -o server -I../libzmq/include -I../cppzmq -L../libzmq/build/lib -lzmq -Wl,-rpath,. 

cl /std:c++17 client.cpp -Fe:client.exe -Ic:\Users\cupcake\github\vcpkg\installed\x64-windows\include\ /link c:\Users\cupcake\github\vcpkg\installed\x64-windows\lib\libzmq-mt-4_3_5.lib

cl /std:c++17 server.cpp -Fe:server.exe -Ic:\Users\cupcake\github\vcpkg\installed\x64-windows\include\ /link c:\Users\cupcake\github\vcpkg\installed\x64-windows\lib\libzmq-mt-4_3_5.lib



clang++ -o bin/Darwin/client obj/Darwin/client.o -mmacosx-version-min=11.0 -isysroot /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk -framework Cocoa -framework IOKit -framework CoreVideo -framework CoreFoundation -framework Accelerate -fvisibility=hidden -O5 -rpath @executable_path -weak_library ./lib/libvulkan.dylib -L./lib -L../libzmq/build/lib -lbella_engine_sdk -lm -lzmq -ldl

```