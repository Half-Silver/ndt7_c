#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <errno.h>

static double parse_ndt7_output(const char *output) {
    const char *ptr = output;
    double packet_loss = -1.0;
    
    // Look for packet loss in the output
    ptr = strstr(output, "\"PacketLoss\":");
    if (ptr) {
        packet_loss = atof(ptr + 13); // Skip past "\"PacketLoss\":" (13 chars)
    }
    
    return packet_loss;
}

static char* find_ndt7_server() {
    // Use a known working server
    return strdup("ndt7-mlab1-lga03.measurement-lab.org");
}

int main() {
    printf("Starting NDT7 network test...\n");
    
    // Find a working NDT7 server
    char *server = find_ndt7_server();
    if (!server) {
        printf("Could not find a working NDT7 server\n");
        return 1;
    }
    
    printf("Using NDT7 server: %s\n", server);
    
    // Create a temporary file for the output
    char tmp_path[] = "/tmp/ndt7_output_XXXXXX";
    int tmp_fd = mkstemp(tmp_path);
    if (tmp_fd == -1) {
        perror("Failed to create temporary file");
        free(server);
        return 1;
    }
    close(tmp_fd);
    
    printf("Running NDT7 test (this may take a moment)...\n");
    
    // Run ndt7-client and capture its output
    printf("Forking to run ndt7-client...\n");
    pid_t pid = fork();
    if (pid == -1) {
        perror("fork failed");
        unlink(tmp_path);
        free(server);
        return 1;
    }
    
    if (pid == 0) {
        // Child process
        int fd = open(tmp_path, O_WRONLY | O_TRUNC);
        if (fd == -1) {
            perror("open");
            _exit(1);
        }
        
        // Redirect stdout and stderr to our file
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);
        close(fd);
        
        // Print the exact command we're about to run
        printf("Executing: /Users/halfsilver/go/bin/ndt7-client -format json -server %s\n", server);
        
        // Execute ndt7-client with the found server
        execlp("/Users/halfsilver/go/bin/ndt7-client", "ndt7-client",
              "-format", "json",
              "-server", server,
              (char *)NULL);
        
        // If we get here, execlp failed
        perror("execlp failed");
        printf("Error details: %s\n", strerror(errno));
        _exit(1);
    }
    
    // Parent process
    int status;
    printf("Waiting for ndt7-client to complete...\n");
    waitpid(pid, &status, 0);
    
    if (WIFEXITED(status)) {
        printf("ndt7-client exited with status: %d\n", WEXITSTATUS(status));
        
        if (WEXITSTATUS(status) == 0) {
            // Read the output file
            FILE *f = fopen(tmp_path, "r");
            if (f) {
                char buffer[8192];
                size_t count = fread(buffer, 1, sizeof(buffer) - 1, f);
                fclose(f);
                
                if (count > 0) {
                    buffer[count] = '\0';
                    printf("Raw output:\n%s\n", buffer);  // Debug output
                    
                    double packet_loss = parse_ndt7_output(buffer);
                    if (packet_loss >= 0) {
                        printf("Packet loss: %.2f%%\n", packet_loss);
                        unlink(tmp_path);
                        free(server);
                        return 0;
                    } else {
                        printf("Failed to parse packet loss from output\n");
                        
                        // Print first 200 chars of output for debugging
                        printf("First 200 chars of output: %.*s\n", 200, buffer);
                    }
                }
            }
        }
    }
    
    printf("Failed to run NDT7 test. Possible issues:\n");
    printf("1. Check your internet connection\n");
    printf("2. Verify the ndt7-client is installed at /Users/halfsilver/go/bin/ndt7-client\n");
    printf("3. Try running the command manually to check for errors:\n");
    printf("   /Users/halfsilver/go/bin/ndt7-client -format json -server %s\n", server);
    
    // Check if the file exists and is executable
    if (access("/Users/halfsilver/go/bin/ndt7-client", X_OK) == -1) {
        printf("Error: ndt7-client is not found or not executable at /Users/halfsilver/go/bin/ndt7-client\n");
    }
    unlink(tmp_path);
    free(server);
    return 1;
}