# bellatui

Command line bella renderer with encrypted networking ,text user interface and file monitoring.

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

### Precompiled Binaries

[Windows](https://a4g4.c14.e2-1.dev/bellatui/bellatui-windows.zip)

[MacOS](https://a4g4.c14.e2-1.dev/bellatui/bellatui-mac.zip)
```
Apple Gatekeeper blocks non-notarized executables by default.
```

[Ubuntu Linux](https://a4g4.c14.e2-1.dev/bellatui/bellatui-linux.tar.gz)
```
apt install -y libsodium-dev
```


# Build 
```
workdir/
├── bella_engine_sdk/
├── libzmq/
├── cppzmq/
├── efsw/
├── belatui/

( additional Windows package manager dependency )
├── vcpkg/

( additional MacOS package manager dependency )
└── homebrew/
```
Download SDK for your OS and drag bella_engine_sdk into your workdir. On Windows rename unzipped folder by removing version ie bella_engine_sdk-24.6.0 -> bella_engine_sdk

- [bella_engine_sdk MacOS](https://downloads.bellarender.com/bella_engine_sdk-24.6.0.dmg)
- [bella_engine_sdk Linux](https://downloads.bellarender.com/bella_engine_sdk-24.6.0.tar.gz)
- [bella_engine_sdk Win](https://downloads.bellarender.com/bella_engine_sdk-24.6.0.zip)


## MacOS
Install Cmake to /Applications
```
curl -LO https://github.com/Kitware/CMake/releases/download/v3.31.6/cmake-3.31.6-macos-universal.dmg
open cmake-3.31.6-macos-universal.dmg
```
Install Xcode

```
mkdir workdir
cd workdir
mkdir homebrew
curl -L https://github.com/Homebrew/brew/tarball/master | tar xz --strip-components 1 -C homebrew
eval "$(homebrew/bin/brew shellenv)"
brew update --force --quiet
brew install libsodium
brew install pkg-config
cd ..
git clone https://github.com/zeromq/libzmq
mkdir -p libzmq/build
cd libzmq/build
/Applications/CMake.app/Contents/bin/cmake .. -DENABLE_CURVE=ON -DWITH_LIBSODIUM=../../homebrew/Cellar/libsodium/1.0.20/include/sodium -DSODIUM_INCLUDE_DIRS=~/homebrew/Cellar/libsodium/1.0.20/include -DSODIUM_LIBRARIES=~/homebrew/Cellar/libsodium/1.0.20/lib/libsodium.a
make -j4
cd ../..
git clone https://github.com/zeromq/cppzmq
git clone https://github.com/SpartanJ/efsw.git
mkdir -p efsw/build
cd efsw/build
/Applications/CMake.app/Contents/bin/cmake ..
make -j4
cd ../..
git clone https://github.com/oomer/bellatui.git
cd bellatui
make all -j4
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
dnf install -y pkg-config
```

[todo] makefile needs this path for redhat
```
      SODDIR          = /usr/lib64/
```

### building libzmq cppzmq
```
mkdir workdir
cd workdir
git clone https://github.com/zeromq/libzmq
cd libzmq
mkdir build
cd build
//cmake .. -DENABLE_CURVE=ON -DWITH_LIBSODIUM=/usr/include/sodium
cmake .. -DENABLE_DRAFTS=OFF -DWITH_TLS=OFF -DENABLE_CURVE=ON -DWITH_LIBSODIUM=/usr/include/sodium
make -j4
cd ../..
git clone https://github.com/zeromq/cppzmq
cd cppzmq
mkdir build
cd build
cmake ..
cd ../..
git clone https://github.com/SpartanJ/efsw.git

mkdir -p efsw/build
cd efsw/build
cmake ..
make -j4
```

### compiling bellatui
```
cd ../..
git clone https://github.com/oomer/bellatui.git
cd bellatui
make all -j4
```

# Windows
https://aka.ms/vs/17/release/vs_BuildTools.exe
[ ] Desktop development with C++

Get bella_engine_sdk

#### x64 Developer console
```
git clone https://github.com/microsoft/vcpkg.git
cd vcpkg
bootstrap-vcpkg.bat
vcpkg install zeromq[sodium]:x64-windows 
vcpkg.exe install cppzmq:x64-windows
vcpkg integrate install
cd ..
git clone https://github.com/SpartanJ/efsw.git
mkdir -p efsw/build
cd efsw/build
cmake ..
msbuild efsw.sln /p:Configuration=Release /p:Platform=x64
cd ../..
git clone https://github.com/oomer/bellatui.git

msbuild bellatui.vcxproj /p:Configuration=release /p:Platform=x64 /p:PlatformToolset=v143
```




