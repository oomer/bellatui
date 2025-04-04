/*
 * BellaTUI - A Client-Server Rendering Application
 * 
 * This application provides a command-line interface for a rendering system called Bella.
 * It consists of two main parts:
 * 1. A server component that handles rendering operations
 * 2. A client component that sends commands and files to the server
 *
 * The application uses ZeroMQ (ZMQ) for secure network communication between client and server.
 * Key features:
 * - Secure communication using CURVE encryption
 * - File transfer capabilities (.bsz files)
 * - Real-time rendering status updates
 * - Heartbeat monitoring to check connection status
 */

#include <iostream>
#include <fstream>
#include <thread>
#include <zmq.hpp>
#include <vector>
#include <chrono>

#include <string>
#include <sstream> // For string streams
#include <atomic>
#include <mutex> // Add this line for std::mutex and std::lock_guard
#include <map> // Add this line for std::map


#include <cstdlib> // For std::system
#include <stdexcept> // For std::runtime_error

#ifdef _WIN32
#include <windows.h> // For ShellExecuteW
#include <shellapi.h> // For ShellExecuteW
#include <codecvt> // For wstring_convert
#elif defined(__APPLE__) || defined(__linux__)
#include <unistd.h> // For fork, exec
#include <sys/wait.h> // For waitpid
#endif

#include <efsw/FileSystem.hpp> // For file watching
#include <efsw/System.hpp> // For file watching
#include <efsw/efsw.hpp> // For file watching
#include <iostream>
#include <signal.h>


#include "../bella_engine_sdk/src/bella_sdk/bella_engine.h" // For rendering
#include "../bella_engine_sdk/src/dl_core/dl_fs.h" // For rendering
using namespace dl;
using namespace dl::bella_sdk;

/// A class that manages a queue of files to render with both FIFO order and fast lookups
class RenderQueue {
public:
    // Default constructor
    RenderQueue() = default;

    // Move constructor
    RenderQueue(RenderQueue&& other) noexcept {
        std::lock_guard<std::mutex> lock(other.mutex);
        pathVector = std::move(other.pathVector);
        pathMap = std::move(other.pathMap);
    }

    // Move assignment operator
    RenderQueue& operator=(RenderQueue&& other) noexcept {
        if (this != &other) {
            std::lock_guard<std::mutex> lock1(mutex);
            std::lock_guard<std::mutex> lock2(other.mutex);
            pathVector = std::move(other.pathVector);
            pathMap = std::move(other.pathMap);
        }
        return *this;
    }

    // Delete copy operations since mutexes can't be copied
    RenderQueue(const RenderQueue&) = delete;
    RenderQueue& operator=(const RenderQueue&) = delete;

    // Add a file to the queue if it's not already there
    bool push(const dl::String& path) {
        std::lock_guard<std::mutex> lock(mutex);
        if (pathMap.find(path) == pathMap.end()) {
            pathVector.push_back(path);
            pathMap[path] = true;
            return true;
        }
        return false;
    }

    // Get the next file to render (FIFO order)
    bool pop(dl::String& outPath) {
        std::lock_guard<std::mutex> lock(mutex);
        if (!pathVector.empty()) {
            outPath = pathVector.front();
            pathVector.erase(pathVector.begin());
            pathMap.erase(outPath);
            return true;
        }
        return false;
    }

    // Remove a specific file by name
    bool remove(const dl::String& path) {
        std::lock_guard<std::mutex> lock(mutex);
        if (pathMap.find(path) != pathMap.end()) {
            // Remove from vector using erase-remove idiom
            pathVector.erase(
                std::remove(pathVector.begin(), pathVector.end(), path),
                pathVector.end()
            );
            // Remove from map
            pathMap.erase(path);
            return true;
        }
        return false;
    }

    // Check if a file exists in the queue
    bool contains(const dl::String& path) const {
        std::lock_guard<std::mutex> lock(mutex);
        return pathMap.find(path) != pathMap.end();
    }

    // Get the number of files in the queue
    size_t size() const {
        std::lock_guard<std::mutex> lock(mutex);
        return pathVector.size();
    }

    // Check if the queue is empty
    bool empty() const {
        std::lock_guard<std::mutex> lock(mutex);
        return pathVector.empty();
    }

    // Clear all files from the queue
    void clear() {
        std::lock_guard<std::mutex> lock(mutex);
        pathVector.clear();
        pathMap.clear();
    }

private:
    std::vector<dl::String> pathVector;  // Maintains FIFO order
    std::map<dl::String, bool> pathMap;  // Enables fast lookups
    mutable std::mutex mutex;            // Thread safety
};

std::atomic<bool> active_render(false);
RenderQueue renderQueue;  // Replace the old vector and map with our new class
std::mutex renderQueueMutex;  // Add mutex for thread safety
std::vector<dl::String> renderDelete; // This is the efsw queue for when we delete a file
std::mutex renderDeleteMutex;  // Add mutex for thread safety

dl::String currentRender;
std::mutex currentRenderMutex;  // Add mutex for thread safety

// Queues for incoming files from the efsw watcher
RenderQueue incomingDeleteQueue;  
RenderQueue incomingRenderQueue;  
std::mutex incomingDeleteQueueMutex;  // Add mutex for thread safety
std::mutex incomingRenderQueueMutex;  // Add mutex for thread safety


/// Processes a file action
class UpdateListener : public efsw::FileWatchListener {
  public:
	UpdateListener() : should_stop_(false) {}

	void stop() {
		should_stop_ = true;
	}

	std::string getActionName( efsw::Action action ) {
		switch ( action ) {
			case efsw::Actions::Add:
				return "Add";
			case efsw::Actions::Modified:
				return "Modified";
			case efsw::Actions::Delete:
				return "Delete";
			case efsw::Actions::Moved:
				return "Moved";
			default:
				return "Bad Action";
		}
	}

	void handleFileAction( efsw::WatchID watchid, const std::string& dir,
						   const std::string& filename, efsw::Action action,
						   std::string oldFilename = "" ) override {
		if (should_stop_) return;  // Early exit if we're stopping
		
		std::string actionName = getActionName( action ); 
		/*std::cout << "Watch ID " << watchid << " DIR ("
				  << dir + ") FILE (" +
						 ( oldFilename.empty() ? "" : "from file " + oldFilename + " to " ) +
						 filename + ") has event "
				  << actionName << std::endl;*/
		if (actionName == "Delete") {
            if (active_render || !incomingRenderQueue.empty()) { 
                dl::String belPath = (dir +  filename).c_str();
                if (belPath.endsWith(".bsz")) {
                    {
                        std::lock_guard<std::mutex> lock(incomingDeleteQueueMutex);
                        if (!incomingDeleteQueue.contains(belPath)) {
                            incomingDeleteQueue.push(belPath);
                            std::cout << "\n==" << "STOP RENDER: " << belPath.buf() << "\n==" << std::endl;
                        }
                    }
                }
            }
		}
		if (actionName == "Add" || actionName == "Modified") {
			dl::String belPath = (dir + filename).c_str();
			if (should_stop_) return;  // Check again before starting render
			if (belPath.endsWith(".bsz")) {
                {
                    std::lock_guard<std::mutex> lock(incomingRenderQueueMutex);
                    if (!incomingRenderQueue.contains(belPath)) {
                        incomingRenderQueue.push(belPath);
                        std::cout << "\n==" << "RENDER QUEUED: " << belPath.buf() << "\n==" << std::endl;
                    }
                }
			}
		}
	}
  private:
	std::atomic<bool> should_stop_; // ctrl-c was not working, so we use this to stop the thread
};

// Global state variables
std::string initializeGlobalLicense();        // Function to return license text
std::string initializeGlobalThirdPartyLicences(); // Function to return third-party licenses
std::atomic<bool> connection_state (false);   // Tracks if client/server are connected
std::atomic<bool> abort_state (false);        // Used to signal program termination
std::atomic<bool> server (false);             // Indicates if running in server mode
UpdateListener* global_ul = nullptr;          // Global pointer to UpdateListener

// Function declarations
std::string get_pubkey_from_srv(std::string server_address, uint16_t publickey_port);  // Gets server's public key for encryption


bool STOP = false;

void sigend( int ) {
	std::cout << std::endl << "Bye bye" << std::endl;
	STOP = true;
	if (global_ul) {  // Use the global pointer
		global_ul->stop();
	}
	// Give a short time for cleanup
	std::this_thread::sleep_for(std::chrono::milliseconds(100));
	exit(0);  // Force exit after cleanup
}

efsw::WatchID handleWatchID( efsw::WatchID watchid ) {
	switch ( watchid ) {
		case efsw::Errors::FileNotFound:
		case efsw::Errors::FileRepeated:
		case efsw::Errors::FileOutOfScope:
		case efsw::Errors::FileRemote:
		case efsw::Errors::WatcherFailed:
		case efsw::Errors::Unspecified: {
			std::cout << efsw::Errors::Log::getLastErrorLog().c_str() << std::endl;
			break;
		}
		default: {
			std::cout << "Added WatchID: " << watchid << std::endl;
		}
	}
	return watchid;
}


static int s_logCtx = 0;
static void log(void* /*ctx*/, LogType type, const char* msg)
{
    switch (type)
    {
    case LogType_Info:
        DL_PRINT("[INFO] %s\n", msg);
        break;
    case LogType_Warning:
        DL_PRINT("[WARN] %s\n", msg);
        break;
    case LogType_Error:
        DL_PRINT("[ERROR] %s\n", msg);
        break;
    case LogType_Custom:
        DL_PRINT("%s\n", msg);
        break;
    }
}

// Main client communication thread
void client_thread( std::string server_pkey, 
                    std::string client_pkey, 
                    std::string client_skey,
                    std::string server_address,
                    uint16_t command_port); 

// Utility function to open files with system default program
void openFileWithDefaultProgram(const std::string& filePath);

// Helper function to check file extensions
bool ends_with_suffix(const std::string& str, const std::string& suffix);

// Server function to handle initial key exchange
void pkey_server(const std::string& pub_key, uint16_t publickey_port);

/*
 * MyEngineObserver Class
 * This class receives callbacks from the Bella rendering engine to track rendering progress.
 * It implements the EngineObserver interface and provides methods to:
 * - Handle render start/stop events
 * - Track rendering progress
 * - Handle error conditions
 * - Store and retrieve the current progress state
 */
struct MyEngineObserver : public EngineObserver
{
public:
    // Called when a rendering pass starts
    void onStarted(String pass) override
    {
        std::cout << "Started pass " << pass.buf() << std::endl;
        logInfo("Started pass %s", pass.buf());
    }

    // Called to update the current status of rendering
    //void onStatus(String pass, String status) override
    //{
    //    logInfo("%s [%s]", status.buf(), pass.buf());
    //}

    // Called to update rendering progress (percentage, time remaining, etc)
    void onProgress(String pass, Progress progress) override
    {
        std::cout << progress.toString().buf() << std::endl;
        setString(new std::string(progress.toString().buf()));
        logInfo("%s [%s]", progress.toString().buf(), pass.buf());
    }

    void onImage(String pass, Image image) override
    {
        logInfo("We got an image %d x %d.", (int)image.width(), (int)image.height());
    }  

    // Called when an error occurs during rendering
    void onError(String pass, String msg) override
    {
        logError("%s [%s]", msg.buf(), pass.buf());
    }

    // Called when a rendering pass completes
    void onStopped(String pass) override
    {
        logInfo("Stopped %s", pass.buf());
        active_render = false;
    }

    // Returns the current progress as a string
    std::string getProgress() const {
        std::string* currentProgress = progressPtr.load();
        if (currentProgress) {
            return *currentProgress;
        } else {
            return "";
        }
    }

    // Cleanup resources in destructor
    ~MyEngineObserver() {
        setString(nullptr);
    }
private:
    // Thread-safe pointer to current progress string
    std::atomic<std::string*> progressPtr{nullptr};

    // Helper function to safely update the progress string
    void setString(std::string* newStatus) {
        std::string* oldStatus = progressPtr.exchange(newStatus);
        delete oldStatus;  // Clean up old string if it exists
    }
};

// Main server thread that handles client requests
void server_thread(     std::string server_skey, 
                        uint16_t command_port,
                        bool test_render,
                        Engine& engine,
                        MyEngineObserver& engineObserver);

void render_thread( Engine& engine,
                    MyEngineObserver& engineObserver);

/*
 * Heartbeat Monitoring System
 * 
 * This function implements a heartbeat mechanism to monitor the connection between client and server.
 * It runs in a separate thread and:
 * - For server: listens for periodic messages from client
 * - For client: sends periodic messages to server
 * If either side stops receiving messages, it marks the connection as dead.
 *
 * Parameters:
 * - server_pkey: Server's public key (used by client)
 * - server_skey: Server's secret key (used by server)
 * - client_pkey: Client's public key (used by client)
 * - client_skey: Client's secret key (used by client)
 * - is_server: Boolean indicating if running in server mode
 * - server_address: Address of the server (used by client)
 * - heartbeat_port: Port number for heartbeat communication
 */
void heartbeat_thread(  std::string server_pkey, 
                        std::string server_skey, 
                        std::string client_pkey, 
                        std::string client_skey, 
                        bool is_server,  
                        std::string server_address,  
                        uint16_t heartbeat_port ) { 

    zmq::context_t ctx;  // Create ZMQ context
    zmq::socket_t heartbeat_sock; // Socket for heartbeat messages

    if(is_server) {
        // Server mode: Listen for client heartbeats
        heartbeat_sock = zmq::socket_t(ctx, zmq::socket_type::rep);
        heartbeat_sock.set(zmq::sockopt::curve_server, true);
        heartbeat_sock.set(zmq::sockopt::curve_secretkey, server_skey);
        std::string url = "tcp://*:" + std::to_string(heartbeat_port);
        heartbeat_sock.bind(url);
        
        while(true) {
            // Only check heartbeats when client is connected
            if (connection_state == true) {
                // Wait up to 5 seconds for client heartbeat
                zmq::pollitem_t response_item = { heartbeat_sock, 0, ZMQ_POLLIN, 0 };
                zmq::poll(&response_item, 1, 5000);

                if (response_item.revents & ZMQ_POLLIN) {
                    // Received heartbeat from client
                    zmq::message_t message;
                    heartbeat_sock.recv(message, zmq::recv_flags::none);
                    heartbeat_sock.send(zmq::message_t("ACK"), zmq::send_flags::dontwait);
                } else {
                    // No heartbeat received - mark connection as dead
                    std::cout << "Bella Client Lost" << std::endl;
                    connection_state = false;
                }
            } 
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        } 
    } else {
        // Client mode: Send heartbeats to server
        zmq::socket_t heartbeat_sock (ctx, zmq::socket_type::req);
        // Set up encryption keys
        heartbeat_sock.set(zmq::sockopt::curve_serverkey, server_pkey);
        heartbeat_sock.set(zmq::sockopt::curve_publickey, client_pkey);
        heartbeat_sock.set(zmq::sockopt::curve_secretkey, client_skey);
        heartbeat_sock.set(zmq::sockopt::linger, 1);
        
        std::string url = "tcp://" + server_address + ":" + std::to_string(heartbeat_port);
        heartbeat_sock.connect(url);

        while (true) {
            // Check if we should stop
            if(abort_state.load()==true) {
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));

            if(connection_state == true) {
                // Send heartbeat to server
                heartbeat_sock.send(zmq::message_t("ACK"), zmq::send_flags::none);
                
                // Wait for server response
                zmq::pollitem_t response_item = { heartbeat_sock, 0, ZMQ_POLLIN, 0 };
                zmq::poll(&response_item, 1, 5000);
                
                if (response_item.revents & ZMQ_POLLIN) {
                    // Got response from server
                    zmq::message_t msg_response;
                    heartbeat_sock.recv(msg_response, zmq::recv_flags::none);
                } else {
                    // No response - mark connection as dead
                    std::cout << "Bella Server is unavailable" << std::endl;
                    connection_state = false;
                    break;
                }
            }
        }
    }
    // Clean up resources
    heartbeat_sock.close();
    ctx.close();
}

void file_watcher_thread(const std::string& watch_path = "") {
    bool commonTest = true;
    bool useGeneric = false;
    
    global_ul = new UpdateListener();
    efsw::FileWatcher fileWatcher(useGeneric);

    fileWatcher.followSymlinks(false);
    fileWatcher.allowOutOfScopeLinks(false);

    if (!watch_path.empty() && dl::fs::exists(watch_path.data())) {
        commonTest = false;
        if (fileWatcher.addWatch(watch_path, global_ul, true) > 0) {
            fileWatcher.watch();
            std::cout << "Watching directory: " << watch_path << std::endl;
        } else {
            std::cout << "Error trying to watch directory: " << watch_path << std::endl;
            std::cout << efsw::Errors::Log::getLastErrorLog().c_str() << std::endl;
            return;
        }
    } else if (commonTest) {
        std::string CurPath(efsw::System::getProcessPath());
        std::cout << "CurPath: " << CurPath.c_str() << std::endl;
        fileWatcher.watch();
        handleWatchID(fileWatcher.addWatch(CurPath + "test", global_ul, true));
    }

    while(STOP == false) {
        efsw::System::sleep(500);
    }

    delete global_ul;
    global_ul = nullptr;
}

/*
 * Main Program Entry Point
 * 
 * This function initializes the application and handles command-line arguments.
 * It can run in either server or client mode:
 * - Server mode: Starts rendering engine and waits for client connections
 * - Client mode: Connects to server and sends commands
 *
 * Command-line arguments:
 * --server        : Run in server mode
 * --serverAddress : IP address of server (for client mode)
 * --commandPort   : Port for main command communication
 * --heartbeatPort : Port for connection monitoring
 * --publickeyPort : Port for initial key exchange
 * --testRender    : Use small resolution for testing
 * --thirdparty    : Show third-party licenses
 * --licenseinfo   : Show license information
 */
 #include "dl_core/dl_main.inl"
int DL_main(Args& args)
{
    // Default configuration values
    const size_t chunk_size = 65536;
    std::string server_address = "localhost";
    uint16_t command_port = 5797;
    uint16_t heartbeat_port = 5798;
    uint16_t publickey_port = 5799;
    bool test_render = false;

    Engine engine;
    engine.scene().loadDefs();
    MyEngineObserver engineObserver;
    engine.subscribe(&engineObserver);

    // Very early on, we will subscribe to the global bella logging callback, and ask to flush
    // any messages that may have accumulated prior to this point.
    //
    subscribeLog(&s_logCtx, log);
    flushStartupMessages();


    // Register command-line arguments
    args.add("sa",  "serverAddress", "",   "Bella render server ip address");
    args.add("cp",  "commandPort",   "",   "tcp port for zmq server socket for commands");
    args.add("hp",  "heartbeatPort", "",   "tcp port for zmq server socket for heartbeats");
    args.add("pp",  "publickeyPort", "",   "tcp port for zmq server socket for server pubkey");
    args.add("s",   "server",        "",   "turn on server mode");
    args.add("tr",  "testRender",    "",   "force res to 100x100");
    args.add("tp",  "thirdparty",    "",   "prints third party licenses");
    args.add("li",  "licenseinfo",   "",   "prints license info");
    args.add("ef",  "efsw",   "",   "mode efsw");
    args.add("wd",  "watchdir",   "",   "mode file warch");

    // Handle special command-line options
    if (args.versionReqested())
    {
        printf("%s", bellaSdkVersion().toString().buf());
        return 0;
    }

    if (args.helpRequested())
    {
        printf("%s", args.help("SDK Test", fs::exePath(), bellaSdkVersion().toString()).buf());
        return 0;
    }
    std::string path=".";

    if (args.have("--watchdir")) {
        path = args.value("--watchdir").buf();
    }


    //EFSW mode alwys on
    // Create the file watcher thread
    std::thread watcher_thread(file_watcher_thread, path);
    // Don't wait for the thread to finish here, let it run in background
    watcher_thread.detach();
    
    /*if (args.have("--efswxxxxx"))
    {
        std::cout << "EFSW mode" << std::endl;
        signal( SIGABRT, sigend );
        signal( SIGINT, sigend );
        signal( SIGTERM, sigend );

        //std::cout << "Press ^C to exit demo" << std::endl;

        std::string path;
        if (args.have("--watchdir")) {
            path = args.value("--watchdir").buf();
        }

        // Create the file watcher thread
        std::thread watcher_thread(file_watcher_thread, path);
        
        // Don't wait for the thread to finish here, let it run in background
        watcher_thread.detach();
    }*/
    
    // Show license information if requested
    if (args.have("--licenseinfo"))
    {
        std::cout << initializeGlobalLicense() << std::endl;
        return 0;
    }
 
    // Show third-party licenses if requested
    if (args.have("--thirdparty"))
    {
        std::cout << initializeGlobalThirdPartyLicences() << std::endl;
        return 0;
    }
 
    // Check if running in server mode
    if (args.have("--server"))
    {
        server=true;
    }
    
    // Enable test rendering if requested
    if (args.have("--testRender"))
    {
        test_render=true;
    }

    // Parse server address (for client mode)
    if (args.have("--serverAddress")) 
    {
        server_address = args.value("--serverAddress").buf();
    }

    // Parse port numbers if provided
    if (args.have("--heartbeatPort")) 
    {
        String argString = args.value("--heartbeatPort");
        uint16_t u16; 
        if (argString.parse(u16)) {
            heartbeat_port = u16;
        } else {
            std::cerr << "invalid --heartbeatPort" << argString << std::endl;
        }
    }

    if (args.have("--commandPort")) 
    {
            String argString = args.value("--commandPort");
            uint16_t u16; 
            if (argString.parse(u16)) {
                command_port = u16;
            } else {
            std::cerr << "invalid --commandPort" << argString << std::endl;
            }
    }

    if (args.have("--publickeyPort")) 
    {
            String argString = args.value("--publickeyPort");
            uint16_t u16; 
            if (argString.parse(u16)) {
                publickey_port = u16;
            } else {
            std::cerr << "invalid --commandPort" << argString << std::endl;
            }
    }


    // Generate brand new keypair on launch
    // [TODO] Add client side public key fingerprinting for added security
    if(server.load()) {
        std::cout << "BellaTUI server started ..." << std::endl;
        char server_skey[41] = { 0 };
        char server_pkey[41] = { 0 };
        if ( zmq_curve_keypair(&server_pkey[0], &server_skey[0])) {
            // 1 is fail
            std::cout << "\ncurve keypair gen failed.";
            exit(EXIT_FAILURE);
        }
        std::thread server_t(server_thread, server_skey, command_port, test_render, std::ref(engine), std::ref(engineObserver));
        std::thread render_t(render_thread, std::ref(engine), std::ref(engineObserver));
        ///std::thread heartbeat_t(heartbeat_thread, server_skey, server.load(), 5555);
        std::thread heartbeat_t(heartbeat_thread,   //function
                                "",                 //NA Public server key 
                                server_skey,        //Secret servery key 
                                "",                 //NA Public client key 
                                "",                 //NA Secret client key 
                                true,               //is server 
                                "",                 //FQDN or ip address of server 
                                heartbeat_port);              //bind port
                                       //
        while(true) { // awaiting new client loop
            std::cout << "Awaiting new client ..." << std::endl;
            pkey_server(server_pkey, publickey_port); // blocking wait client to get public key
            std::cout << "Client connected" << std::endl; 
            connection_state = true;

            while(true) { // inner loop
                if (connection_state.load()==false) { 
                    std::cout << "Client connection dead" << std::endl;
                    break; // Go back to awaiting client
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
        }
        //abort_state==true;
        server_t.join();
        heartbeat_t.join();
        return 0;      

    } else { //Client
        char client_skey[41] = { 0 };
        char client_pkey[41] = { 0 };
        if ( zmq_curve_keypair(&client_pkey[0], &client_skey[0])) {
            // 1 is fail
            std::cout << "\ncurve keypair gen failed.";
            exit(EXIT_FAILURE);
        }

        std::string server_pkey = get_pubkey_from_srv(server_address, publickey_port);
        std::string client_pkey_str(client_pkey);
        std::string client_skey_str(client_skey);

        // Multithreaded
        std::thread command_t(  client_thread, 
                                server_pkey, 
                                client_pkey_str, 
                                client_skey_str,
                                server_address,
                                command_port);
        //std::thread heartbeat_t(heartbeat_thread, server_pkey, client_pkey_str, client_skey_str);
        std::thread heartbeat_t(heartbeat_thread,   //function
                                server_pkey,        //Public server key  
                                "",                 //NA Secret server key
                                client_pkey_str,    //Public client key
                                client_skey_str,    //Secret client key
                                false,              //is server
                                server_address,         //Server FQDN or ip address
                                heartbeat_port);              //connect port

        while (true) {
            /*if (!heartbeat_state.load()) {
                std::cout << "Dead" << std::endl;
                abort_state==true;
                break;
            }*/
            if (connection_state.load() ==  false) {
                std::cout << "Dead2" << std::endl;
                abort_state==true;
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
    }
}

std::string get_pubkey_from_srv(std::string server_address, uint16_t publickey_port) {
    // No authentication is used, server will give out pubkey to anybody
    // Could use a unique message but since socket is unencrypted this provides
    // no protection. In main loop we establish an encrypted connection with the server
    // now that we have the pubkey and in combo with the client_secret_key we can
    // be secure. 0MQ uses PFS perfect forward security, because this initial
    // back and forth is extended with behind the scenes new keypairs taken care of by
    // 0MQ after we establish our intitial encrypted socket
    zmq::context_t ctx;
    zmq::socket_t pubkey_sock(ctx, zmq::socket_type::req);
    std::string url = "tcp://" + server_address + ":" + std::to_string(publickey_port);
    pubkey_sock.connect(url);
    zmq::message_t z_out(std::string("Bellarender123"));

    try {
        zmq::send_result_t send_result = pubkey_sock.send(z_out, zmq::send_flags::none);
    } catch (const zmq::error_t& e) {
        std::cout << "ERROR" << std::endl;
    }

    std::cout << "\nbellatui connecting to " << server_address << " ..." << std::endl;
    zmq::message_t z_in;
    pubkey_sock.recv(z_in);
    std::string pub_key = z_in.to_string();
    pubkey_sock.close();
    ctx.close();
    std::cout << "Connection to " << server_address << " successful" << std::endl;
    connection_state = true;
    return pub_key;
}

void client_thread( std::string server_pkey, 
                    std::string client_pkey, 
                    std::string client_skey,
                    std::string server_address,
                    uint16_t command_port ) {
    //std::cout << "client thread: " << server_address << " " << command_port << std::endl;
    const size_t chunk_size = 65536;
    zmq::context_t ctx;
    zmq::socket_t command_sock (ctx, zmq::socket_type::req);
    //command_sock.set(zmq::sockopt::sndtimeo, 10000);
    //command_sock.set(zmq::sockopt::rcvtimeo, 10000);
    command_sock.set(zmq::sockopt::curve_serverkey, server_pkey);
    command_sock.set(zmq::sockopt::curve_publickey, client_pkey);
    command_sock.set(zmq::sockopt::curve_secretkey, client_skey);
    command_sock.set(zmq::sockopt::linger, 1); // Close immediately on disconnect
    
    //std::string url = "tcp://" + server_address+ ":" + std::to_string(command_port);
    std::string url = "tcp://" + server_address + ":" + std::to_string(command_port);
    //std::cout << "client thread " << url << std::endl;
    command_sock.connect(url);
    
    std::string input;
    while (true) {
        if(abort_state.load()==true) {
            break;
        }
        std::getline(std::cin, input);
        std::stringstream ss(input);
        std::string arg;
        std::vector<std::string> args;
        while (ss >> arg) {
            args.push_back(arg);
        }

        // Sanity checks on input before sending to server
        int num_args = args.size();
        std::string command;
        if (num_args > 0) {
            command = args[0];
            if ( command == "send") {
                if(num_args == 1) {
                    std::cout << "Please provide a .bsz file" << std::endl;
                    continue;
                }
                if(!ends_with_suffix(args[1],".bsz")) {
                    std::cout << "Only .bsz files can be sent" << std::endl;
                    continue;
                }

                if(!dl::fs::exists(args[1].data())) {
                    std::cout << args[1] << " cannot be found" << std::endl;
                    continue;
                }
                std::cout << "Sending:" << args[1] << std::endl;
            } else if (command == "get") {
                if(num_args == 1) {
                    std::cout << "Please provide image filename" << std::endl;
                    continue;
                }
            } else if (command == "exit") {
                ;
            } else if (command == "render") {
                std::string compoundArg;
                if(num_args > 1) {
                    for (size_t i = 1; i < args.size(); ++i) {
                        compoundArg += args[i];
                        if (i < args.size() - 1) {
                            compoundArg += " "; // Add spaces between arguments
                        }
                    }
                    std::cout << compoundArg << std::endl;
                }
            } else if (command == "hello") {
                ;
            } else if (command == "stat") {
                ;
            } else if (command == "help") {
                std::cout << "\033[32msend file.bsz\033[0m upload bella scene to server\n";
                std::cout << "\033[32mrender\033[0m start render on server\n";
                std::cout << "\033[32mget file.png\033[0m download png from server\n";
                std::cout << "\033[32mstop\033[0m stop render on server\n";
                std::cout << "\033[32mstat\033[0m display progress\n";
                continue;
            } else if (command == "stop") {
                ;
            } else {
                std::cout << "unknown" << std::endl;
                continue;
            }        
        }

        // Sanity check input complete
        // Push to server over encrypted socket
        zmq::message_t server_response;
        zmq::message_t msg_command(command);
        //>>>ZOUT
        command_sock.send(msg_command, zmq::send_flags::none); //SEND
        //std::cout << "Sent: " << input.data() << std::endl;

        //ZIN<<<
        command_sock.recv(server_response, zmq::recv_flags::none); //RECV
        std::string response_str(static_cast<char*>(server_response.data()), server_response.size()-1);
        std::string response_str2(static_cast<char*>(server_response.data()), server_response.size());

        if(response_str=="RDY") { // Server acknowledges readiness for multi message commands
            std::cout << "Server Readiness: " << response_str << std::endl;
            if(command == "exit") {
                exit(0);
            // RENDER
            } else if(command == "render") {
                std::string compoundArg;
                if(num_args > 1) {
                    for (size_t i = 1; i < args.size(); ++i) {
                        compoundArg += args[i];
                        if (i < args.size() - 1) {
                            compoundArg += " "; // Add spaces between arguments
                        }
                    }
                    std::cout << compoundArg << std::endl;
                }
                //>>>ZOUT
                command_sock.send(zmq::message_t("render"), zmq::send_flags::none);
                //ZIN<<<
                command_sock.recv(server_response, zmq::recv_flags::none);
            } else if(command == "stat") {
                //>>>ZOUT
                command_sock.send(zmq::message_t("stat"), zmq::send_flags::none);
                //ZIN<<<
                command_sock.recv(server_response, zmq::recv_flags::none);

            // GET
            } else if(command == "get") {
                std::ofstream output_file(args[1], std::ios::binary); // Open file in binary mode
                if (!output_file.is_open()) {
                    std::cerr << "Error opening file for writing" << std::endl;
                    std::cout << "ERR" << std::endl;
                    continue; // Don't bother server
                } else {
                    while (true) {
                        //>>>ZOUT
                        command_sock.send(zmq::message_t("GO"), zmq::send_flags::none); 
                        zmq::message_t recv_data;
                        //ZIN<<<
                        command_sock.recv(recv_data, zmq::recv_flags::none); // data transfer

                        // inline messaging with data, breaks to exit loop
                        if (recv_data.size() < 8) {
                            std::string recv_string(static_cast<const char*>(recv_data.data()), recv_data.size()-1);
                            //std::string recv_string = recv_data.to_string();
                            if (recv_string == "EOF") {
                                std::cout << "EOF" << std::endl;
                                break; // End of file 
                            } else if(recv_string == "ERR")  { //LIKELY ERR\0 from client, can't find file
                                std::cout << "ERR client read ACK" << std::endl;
                                break; // Err
                            } else {
                                std::cout << "HUH" << recv_string << std::endl;
                                break;
                            }
                        }
                        // by reaching this point we assume binary data ( even 8 bytes will reach here )
                        std::cout << "\033[32m.\033[0m";
                        output_file.write(static_cast<char*>(recv_data.data()), recv_data.size());
                    }
                    output_file.close();
                    try {
                        openFileWithDefaultProgram(args[1]); // Replace with your file path
                        std::cout << "File opened successfully." << std::endl;
                    } catch (const std::runtime_error& e) {
                        std::cerr << "Error: " << e.what() << std::endl;
                    }
                }
            // SEND
            } else if(command == "send") {
                std::string read_file = args[1];
                std::cout << "sending\n";
                std::ifstream binaryInputFile;
                binaryInputFile.open(read_file, std::ios::binary);// for reading
                if (!binaryInputFile.is_open()) {
                    std::cerr << "Error opening file for read" << std::endl;
                    //>>>ZOUT
                    command_sock.send(zmq::message_t("ERR"), zmq::send_flags::none); 
                    ///ZIN<<<
                    command_sock.recv(server_response, zmq::recv_flags::none);
                } else {
                    std::vector<char> send_buffer(chunk_size);
                    std::streamsize bytes_read_in_chunk;
                    while (true) {
                        binaryInputFile.read(send_buffer.data(), chunk_size); // read the file into the buffer
                        bytes_read_in_chunk = binaryInputFile.gcount(); // Actual bytes read
                        if(bytes_read_in_chunk > 0){
                            std::cout << "\033[32m.\033[0m";
                            zmq::message_t message(send_buffer.data(), bytes_read_in_chunk);
                            //>>>ZOUT 
                            command_sock.send(message, zmq::send_flags::none);
                            //ZIN<<<
                            command_sock.recv(server_response, zmq::recv_flags::none);
                        } else {
                            std::cout << "\n";
                            break;
                        }
                    }
                    //<<<ZOUT
                    command_sock.send(zmq::message_t("EOF"), zmq::send_flags::none);
                    //ZIN>>>
                    command_sock.recv(server_response, zmq::recv_flags::none);
                }
            }
        } else {
            std::cout << "Server response: \033[32m" << response_str2 << "\033[0m" << std::endl;
        }
    }
    command_sock.close();
    ctx.close();
}

void server_thread(     std::string server_skey, 
                        uint16_t command_port,
                        bool test_render,
                        Engine& engine,
                        MyEngineObserver& engineObserver) {
    //MyEngineObserver engineObserver;
    //engine.subscribe(&engineObserver);

    zmq::context_t ctx;
    zmq::socket_t command_sock(ctx, zmq::socket_type::rep);  
    //command_sock.set(zmq::sockopt::sndtimeo, 10000);
    //command_sock.set(zmq::sockopt::rcvtimeo, 10000);
    command_sock.set(zmq::sockopt::curve_server, true);
    command_sock.set(zmq::sockopt::curve_secretkey, server_skey);
    //command_sock.set(zmq::sockopt::linger, 100); // Close immediately on disconnect
    std::string url = "tcp://*:" + std::to_string(command_port);
    command_sock.bind(url);
    zmq::message_t client_response; 

    try {
        std::string write_file = "./oomer.bsz";            
        std::string read_file = "./oomer.png";            
        const size_t chunk_size = 65536;
        std::vector<char> sftp_buffer(chunk_size); // Buffer to hold each chunk
        std::ofstream binaryOutputFile;// for writing
        std::ifstream binaryInputFile;// for reading
        while (true) {
            zmq::message_t msg_command; 
            //ZIN<<<
            command_sock.recv(msg_command, zmq::recv_flags::none);
            std::string client_command = msg_command.to_string();
            std::cout << "\033[32mCommand: " << client_command << "\033[0m"<< std::endl;

            if(client_command == "hello"){
                std::cout << "bye" << std::endl;
                //>>>ZOUT
                command_sock.send(zmq::message_t("bye"), zmq::send_flags::none); 
            } else if (client_command == "exit") {
                std::cout << "Client disconnecting..." << std::endl;
                //>>>ZOUT
                command_sock.send(zmq::message_t("RDY"), zmq::send_flags::none); 
                connection_state = false; //<<
            // RENDER
            } else if (client_command == "xxxxrender") {
                std::cout << "start render" << std::endl;

                //>>>ZOUT
                command_sock.send(zmq::message_t("render started...type stat to get progress"), zmq::send_flags::none); 
            } else if (client_command == "stop") {
                std::cout << "stop render" << std::endl;
                engine.stop();
                //>>>ZOUT
                command_sock.send(zmq::message_t("render stopped"), zmq::send_flags::none); 

            //GET
            } else if (client_command == "get") { //REP mode
                std::string read_file = "./oomer.png";
                std::cout << "Executing get command\n";
                std::ifstream binaryInputFile;
                binaryInputFile.open(read_file, std::ios::binary);// for reading
                if (!binaryInputFile.is_open()) {
                    std::cerr << "Error opening file for read" << std::endl;
                    //>>>ZOUT
                    command_sock.send(zmq::message_t("ERR"), zmq::send_flags::none); 
                } else {
                    //>>>ZOUT
                    command_sock.send(zmq::message_t("RDY"), zmq::send_flags::none); 
                    std::vector<char> send_buffer(chunk_size);
                    std::streamsize bytes_read_in_chunk;
                    while (true) {
                        zmq::message_t z_in;
                        //ZIN
                        command_sock.recv(z_in);  // Block until zGo, or any message
                        binaryInputFile.read(send_buffer.data(), chunk_size); // read the file into the buffer
                        bytes_read_in_chunk = binaryInputFile.gcount(); // Actual bytes read
                        if(bytes_read_in_chunk > 0){
                            std::cout << bytes_read_in_chunk << std::endl;
                            zmq::message_t message(send_buffer.data(), bytes_read_in_chunk);
                            //ZOUT
                            command_sock.send(message, zmq::send_flags::none); 
                        } else {
                            //ZOUT
                            command_sock.send(zmq::message_t("EOF"), zmq::send_flags::none); 
                            std::cout << "EOF" << std::endl;
                            break; // Exit when 0 bytes read
                        }
                    }
                }

            } else if (client_command == "stat") {
                std::string currentProgress = engineObserver.getProgress();
                if (!currentProgress.empty()) {
                    std::cout << "Current Progress: " << currentProgress << std::endl;
                    command_sock.send(zmq::message_t(currentProgress), zmq::send_flags::none); 
                } else {
                    command_sock.send(zmq::message_t("ACK"), zmq::send_flags::none); 
                }
            } else if (client_command == "send") {
                std::ofstream output_file("oomer.bsz", std::ios::binary); // Open file in binary mode
                if (!output_file.is_open()) {
                    std::cerr << "Error opening file for writing" << std::endl;
                    //>>>ZOUT
                    command_sock.send(zmq::message_t("ERR"), zmq::send_flags::none); 
                } else { // File handle open and ready
                    //>>>ZOUT
                    command_sock.send(zmq::message_t("RDY"), zmq::send_flags::none); 
                    while (true) {
                        zmq::message_t recv_data;
                        //ZIN<<<
                        command_sock.recv(recv_data, zmq::recv_flags::none);
                        if(recv_data.size() < 8) { // data and signals sent on same socket
                            // Allow for signals up to 8 bytes, EOF, ERR
                            // messages are null terminated requiring -1
                            std::string response_str(static_cast<char*>(recv_data.data()), recv_data.size()-1);
                            if (response_str=="EOF") {
                                //>>>ZOUT
                                command_sock.send(zmq::message_t("ACK"), zmq::send_flags::none);
                                break; // End of file
                            } else if(response_str=="ERR")  {
                                std::cout << "ERR on client" << std::endl;
                                //>>>ZOUT
                                command_sock.send(zmq::message_t("ACK"), zmq::send_flags::none);
                                break; // End of file
                            }
                        }
                        // File write
                        output_file.write(static_cast<char*>(recv_data.data()), recv_data.size());
                        //>>ZOUT
                        command_sock.send(zmq::message_t("ACK"), zmq::send_flags::none);
                    }
                    output_file.close();
                    std::cout << "\033[32mClient uploaded .bsz successfully saved\033[0m" << std::endl;
                    engine.scene().read("oomer.bsz");
                    engine.scene().beautyPass()["outputExt"] = ".png";
                    engine.scene().beautyPass()["outputName"] = "";
                    engine.scene().beautyPass()["overridePath"] = bella_sdk::Node();
                }
            } else { // A unknown REQ sent, acknowledge because req-rep pattern is blocking
                //>>ZOUT
                command_sock.send(zmq::message_t("ACK"), zmq::send_flags::none); 
            }



            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

    } catch (const zmq::error_t& e) {
        // Handle ZMQ-specific exceptions
        std::cerr << "ZMQ error: " << e.what() << std::endl;
        ctx.close();
        command_sock.close();
        //Potentially close sockets, clean up etc.
    } catch (const std::exception& e) {
        // Handle standard exceptions (e.g., std::bad_alloc)
        std::cerr << "Standard exception: " << e.what() << std::endl;
    } catch (...) {
        // Catch any other exceptions
        std::cerr << "Unknown exception caught." << std::endl;
    }
    command_sock.close();
    ctx.close();
}

void render_thread( Engine& engine,
                    MyEngineObserver& engineObserver) {
    // Create persistent instances outside the loop
    RenderQueue renderThreadQueue;
    RenderQueue renderThreadDeleteQueue;

    while (true) {
        // Append items from incoming queues to our persistent queues
        {
            std::lock_guard<std::mutex> lock(incomingRenderQueueMutex);
            // Process each item in the incoming queue and add it to our persistent queue
            dl::String path;
            while (incomingRenderQueue.pop(path)) {
                renderThreadQueue.push(path);
            }
            incomingRenderQueue.clear();
        }
        
        {
            std::lock_guard<std::mutex> lock(incomingDeleteQueueMutex);
            // Process each item in the incoming queue and add it to our persistent queue
            dl::String path;
            while (incomingDeleteQueue.pop(path)) {
                renderThreadDeleteQueue.push(path);
            }
            incomingDeleteQueue.clear();
        }

        // Process the files without holding the mutex
        bool expected = false;
        
        // This is an atomic operation that does two things at once:
        // 1. Checks if active_render equals expected (false)
        // 2. If they are equal, sets active_render to true
        // 
        // The operation is atomic, meaning no other thread can interfere
        // between the check and the set. This prevents two threads from
        // both thinking they can start rendering at the same time.
        //
        // Returns true if the exchange was successful (we got the render slot)
        // Returns false if active_render was already true (someone else is rendering)
        dl::String belPath;
        if (active_render.compare_exchange_strong(expected, true)) {
            // We successfully got the render slot - no one else is rendering
            if (renderThreadQueue.pop(belPath)) {
                std::cout << "\n==" << "RENDERING: " << belPath.buf() << "\n==" << std::endl;
                engine.loadScene(belPath);
                engine.scene().camera()["resolution"]= Vec2 {100, 100};
                engine.start();
                {
                    std::lock_guard<std::mutex> lock(currentRenderMutex);
                    currentRender = belPath; 
                }
            } else {
                active_render = false;  // Release the render slot
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        } else { // someone else is rendering
            std::cout << "Waiting for render slot" << std::endl;

            //std::cout << "Render Queue size: " << renderThreadQueue.size() << std::endl;
            //std::cout << "Delete Queue size: " << renderThreadDeleteQueue.size() << std::endl;
            while (renderThreadDeleteQueue.pop(belPath)) { // pop all the deletes
                std::cout << "renderThreadDeleteQueue contains " << belPath.buf() << " " << renderThreadDeleteQueue.contains(belPath) << std::endl;
                if (belPath == currentRender) {
                    std::cout << "/n==/nStopping render" << belPath.buf() << std::endl;
                    engine.stop();
                    active_render = false;
                } else if (renderThreadQueue.contains(belPath)) { // dequeue deletes
                    renderThreadQueue.remove(belPath);
                } 
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}


void openFileWithDefaultProgram(const std::string& filePath) {
#ifdef _WIN32
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
    std::wstring wideFilePath = converter.from_bytes(filePath);

    HINSTANCE result = ShellExecuteW(nullptr, nullptr, wideFilePath.c_str(), nullptr, nullptr, SW_SHOW);

    if ((intptr_t)result <= 32) {
        throw std::runtime_error("Failed to open file: ShellExecuteW returned " + std::to_string((intptr_t)result));
    }

#elif defined(__APPLE__)
    pid_t pid = fork();
    if (pid == 0) {
        // Child process
        execl("/usr/bin/open", "open", filePath.c_str(), nullptr);
        // If execl fails:
        std::cerr << "Failed to open file: execl failed" << std::endl;
        exit(1); // Exit child process on error
    } else if (pid > 0) {
        // Parent process
        int status;
        waitpid(pid, &status, 0);
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            throw std::runtime_error("Failed to open file: open command failed");
        }
    } else {
        throw std::runtime_error("Failed to open file: fork failed");
    }

#elif defined(__linux__)
    pid_t pid = fork();
    if (pid == 0) {
        // Child process
        execl("/usr/bin/xdg-open", "xdg-open", filePath.c_str(), nullptr);
        // If execl fails:
        std::cerr << "Failed to open file: execl failed" << std::endl;
        exit(1); // Exit child process on error
    } else if (pid > 0) {
        // Parent process
        int status;
        waitpid(pid, &status, 0);
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            throw std::runtime_error("Failed to open file: xdg-open command failed");
        }
    } else {
        throw std::runtime_error("Failed to open file: fork failed");
    }

#else
    // Fallback: Use system, but this is less reliable and secure.
    std::string command = "open \"" + filePath + "\""; // May need to adapt quoting
    int result = std::system(command.c_str());
    if (result != 0) {
        throw std::runtime_error("Failed to open file: system command failed");
    }
#endif
}

bool ends_with_suffix(const std::string& str, const std::string& suffix) {
    if (str.length() >= 4) {
        return str.substr(str.length() - 4) == suffix;
    }
    return false;
}

// Blocking zmq rep socket to pass server_public_key
void pkey_server(const std::string& pub_key, uint16_t publickey_port) {
    zmq::context_t ctx;
    zmq::socket_t sock(ctx, zmq::socket_type::rep);
    std::string url = "tcp://*:" + std::to_string(publickey_port);
    sock.bind(url); 

    zmq::message_t z_in;
    //ZIN<<<
    sock.recv(z_in);
    if (z_in.to_string().compare("Bellarender123") == 0) {
        zmq::message_t z_out(pub_key);
        //ZOUT>>>
        sock.send(z_out, zmq::send_flags::none);
        connection_state = true;
    }
    sock.close();
    ctx.close();
}

std::string initializeGlobalLicense() {
    return R"(
bellatui

Copyright (c) 2025 Harvey Fong

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.)"; }

std::string initializeGlobalThirdPartyLicences() {
return R"(
====

Bella SDK (Software Development Kit)

Copyright Diffuse Logic SCP, all rights reserved.

Permission is hereby granted to any person obtaining a copy of this software
(the "Software"), to use, copy, publish, distribute, sublicense, and/or sell
copies of the Software.

THIS SOFTWARE IS PROVIDED "AS IS" WITHOUT EXPRESS OR IMPLIED WARRANTY. ALL
IMPLIED WARRANTIES OF FITNESS FOR ANY PARTICULAR PURPOSE AND OF MERCHANTABILITY
ARE HEREBY DISCLAIMED.

====

CppZMQ

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to
deal in the Software without restriction, including without limitation the
rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
sell copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
IN THE SOFTWARE.

====

libsodium


ISC License

Copyright (c) 2013-2025
Frank Denis <j at pureftpd dot org>

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

 =====

 libzmq is free software; you can redistribute it and/or modify it under the terms of the Mozilla Public License Version 2.0.)"; }
