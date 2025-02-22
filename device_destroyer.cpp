#include <iostream>
#include <vector>
#include <string>
#include <signal.h>
#include <unistd.h>

// Signal handler for blocking termination signals
void signalHandler(int signum) {
    std::cout << "Termination attempt blocked!\n";
    // Do nothing, effectively blocking the signal
}

int main() {
    // Block termination signals (e.g., SIGINT for Ctrl+C)
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    signal(SIGHUP, signalHandler);
    
    std::vector<std::string> memoryLeak;
    while (true) { // Infinite loop
        std::string largeString(1e6, 'X'); // Allocate 1 million characters per iteration
        std::cout << largeString << "\n";
        memoryLeak.push_back(largeString); // Continuously allocates memory
    }
    return 0; // This line will never be reached
}
