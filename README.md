# bellatui

Command line bella renderer with encrypted networking and text user interface.

## Usage

commands: help, send, get, stat, render, stop

### Server
```
bellatui --server
BellaTUI server started ...
Awaiting new client ...
Client connected
```

### Client
```
bellatui --serverAddress:discord.beantip.ca

bellatui connecting to discord.beantip.ca ...
Connection to discord.beantip.ca successful
send orange-juice.bsz
Sending:orange-juice.bsz
Server Readiness: RDY
sending
.........................................................................
render
Server response: render started...type stat to get progress
stat 
Server response: Saturn | Elapsed: 6s | Bench: 1704
stat 
Server response: Saturn | Elapsed: 41s | Progress: 22.65%
```

## Precompile Binaries

[Windows](https://a4g4.c14.e2-1.dev/bellatui/bellatui-windows.zip)

[MacOS](https://a4g4.c14.e2-1.dev/bellatui/bellatui-mac.zip)
```
Apple Gatekeeper blocks non-notarized executables by default.
```

[Ubuntu Linux](https://a4g4.c14.e2-1.dev/bellatui/bellatui-linux.tar.gz)
```
apt install -y libsodium-dev
```


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
cd ../..
git clone https://github.com/zeromq/cppzmq

git clone https://github.com/oomer/bellatui.git
cd bellatui
make

```

## Linux

### bella_engine_sdk
```
curl -O https://downloads.bellarender.com/bella_engine_sdk-24.6.0.tar.gz
tar -xvf bella_engine_sdk-24.6.0.tar.gz
```

#### ubuntu dependencies
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

#### redhat dependencies
```
dnf groupinstall -y "Development Tools"
dnf install -y libX11-devel
dnf install -y mesa-libGL-devel
dnf install -y libtool
dnf install -y libsodium-devel
dnf install -y cmake
dnf install -y gnutls-devel
dnf install -y pkg-config
```

### building libzmq
```
git clone https://github.com/zeromq/libzmq
cd libzmq
mkdir build
cd build

cmake .. -DENABLE_CURVE=ON -DWITH_LIBSODIUM=/usr/include/sodium

cmake .. -DENABLE_DRAFTS=OFF -DWITH_TLS=OFF -DENABLE_CURVE=ON -DWITH_LIBSODIUM=/usr/include/sodium

make -j4
make install
```

### getting cppzmq headers
```
cd ../..
git clone https://github.com/zeromq/cppzmq
cd cppzmq
mkdir build
cd build
cmake .. 
```

### compiling bellatui
```
cd ../..
git clone https://github.com/oomer/bellatui.git
cd bellatui
make
```

# Windows
https://aka.ms/vs/17/release/vs_BuildTools.exe

[ ] Desktop development wiht C++

Get bella_engine_sdk

#### x64 Developer console
```
git clone https://github.com/microsoft/vcpkg.git
cd vcpkg
vcpkg install zeromq[sodium]:x64-windows 

git clone https://github.com/oomer/bellatui.git

msbuild bellatui.vcxproj /p:Configuration=release /p:Platform=x64 /p:PlatformToolset=v143
```

Build directories expected to be relative
```
--folder
    --bella_engine_sdk
    --bellatui
```



