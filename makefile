
SDKNAME			=bella_engine_sdk
OUTNAME			=bellatui
UNAME           =$(shell uname)

ifeq ($(UNAME), Darwin)

	SDKBASE		= ../bella_engine_sdk

	SDKFNAME    = lib$(SDKNAME).dylib
	INCLUDEDIRS	= -I$(SDKBASE)/src
	INCLUDEDIRS2	= -I../cppzmq
	INCLUDEDIRS3	= -I../libzmq/include
	LIBDIR		= $(SDKBASE)/lib
	ZMQDIR		= ~/homebrew/Cellar/zeromq/4.3.5_1/lib
	LIBDIRS2		= -L../libzmq/build/lib
	LIBDIRS		= -L$(LIBDIR)
	OBJDIR		= obj/$(UNAME)
	BINDIR		= bin/$(UNAME)
	OUTPUT      = $(BINDIR)/$(OUTNAME)

	ISYSROOT	= /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk

	CC			= clang
	CXX			= clang++

	CCFLAGS		= -arch x86_64\
				  -arch arm64\
				  -mmacosx-version-min=11.0\
				  -isysroot $(ISYSROOT)\
				  -fvisibility=hidden\
				  -O3\
				  $(INCLUDEDIRS)\
				  $(INCLUDEDIRS2)\
				  $(INCLUDEDIRS3)\
				  $(LIBDIRS2)

	CFLAGS		= $(CCFLAGS)\
				  -std=c11

	CXXFLAGS    = $(CCFLAGS)\
				  -std=c++11
				
	CPPDEFINES  = -DNDEBUG=1\
				  -DDL_USE_SHARED

	LIBS		= -l$(SDKNAME)\
				  -lm\
				  -lzmq\
				  -ldl

	LINKFLAGS   = -mmacosx-version-min=11.0\
				  -isysroot $(ISYSROOT)\
				  -framework Cocoa\
				  -framework IOKit\
				  -framework CoreVideo\
				  -framework CoreFoundation\
				  -framework Accelerate\
				  -fvisibility=hidden\
				  -O5\
				  -rpath @executable_path\
				  -weak_library $(LIBDIR)/libvulkan.dylib
else

	SDKBASE		= .

	SDKFNAME    = lib$(SDKNAME).so
	INCLUDEDIRS	= -I$(SDKBASE)/src
	LIBDIR		= $(SDKBASE)/lib
	LIBDIRS		= -L$(LIBDIR)
	OBJDIR		= obj/$(UNAME)
	BINDIR		= bin/$(UNAME)
	OUTPUT      = $(BINDIR)/$(OUTNAME)

	CC			= gcc
	CXX			= g++

	CCFLAGS		= -m64\
				  -Wall\
				  -Werror\
				  -fvisibility=hidden\
				  -D_FILE_OFFSET_BITS=64\
				  -O3\
				  $(INCLUDEDIRS)

	CFLAGS		= $(CCFLAGS)\
				  -std=c11

	CXXFLAGS    = $(CCFLAGS)\
				  -std=c++11
				
	CPPDEFINES  = -DNDEBUG=1\
				  -DDL_USE_SHARED

	LIBS		= -l$(SDKNAME)\
				  -lm\
				  -ldl\
				  -lrt\
				  -lpthread\
				  -lX11\
				  -lGL\
				  -lzmq\
				  -lvulkan

	LINKFLAGS   = -m64\
				  -fvisibility=hidden\
				  -O3\
				  -Wl,-rpath,'$$ORIGIN'\
				  -Wl,-rpath,'$$ORIGIN/lib'
endif

OBJS = bellatui.o 
OBJ = $(patsubst %,$(OBJDIR)/%,$(OBJS))

$(OBJDIR)/%.o: %.cpp
	@mkdir -p $(@D)
	$(CXX) -c -o $@ $< $(CXXFLAGS) $(CPPDEFINES)

$(OUTPUT): $(OBJ)
	@mkdir -p $(@D)
	$(CXX) -o $@ $^ $(LINKFLAGS) $(LIBDIRS) $(LIBDIRS2) $(LIBS)
	@cp $(LIBDIR)/$(SDKFNAME) $(BINDIR)/$(SDKFNAME)
	@cp $(ZMQDIR)/libzmq.5.dylib $(BINDIR)/libzmq.5.dylib

.PHONY: clean
clean:
	rm -f $(OBJDIR)/*.o
	rm -f $(OUTPUT)
	rm -f $(BINDIR)/$(SDKFNAME)
