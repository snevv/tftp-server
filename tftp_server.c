#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <strings.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>


#define TFTP_BASE_DIR "./tftp_dir/"

// OPCODES
typedef enum {
    RRQ = 1, // Read Request
    WRQ,     // Write Request
    DATA,    // Data
    ACK,     // Acknowledgement
    ERROR    // Error
} Opcode;

// TFTP ERROR CODES
typedef enum {
    ERR_NOT_DEFINED = 0,        // Not defined, see error message
    ERR_FILE_NOT_FOUND = 1,     // File not found
    ERR_ACCESS_VIOLATION = 2,   // Access violation
    ERR_DISK_FULL = 3,          // Disk full or allocation exceeded
    ERR_ILLEGAL_OPERATION = 4,  // Illegal TFTP operation
    ERR_UNKNOWN_TID = 5,        // Unknown transfer ID
    ERR_FILE_EXISTS = 6,        // File already exists
    ERR_NO_SUCH_USER = 7        // No such user
} TftpErrorCode;

// TFTP Message Structures
typedef struct {
    uint16_t opcode;    // RRQ or WRQ
    char filename[512]; // Null-terminated filename (not sure about this. might have to ask if the file is null terminated)
    char mode[10];      // "octet" mode
} tftp_rrq_wrq_t;

typedef struct {
    uint16_t opcode;    // DATA
    uint16_t block;     // Block number
    char data[512];     // Data payload
} tftp_data_t;

typedef struct {
    uint16_t opcode;    // ACK
    uint16_t block;     // Block number
} tftp_ack_t;

typedef struct {
    uint16_t opcode;    // ERROR
    uint16_t error_code;
    char error_msg[512]; // Error message
} tftp_error_t;

// SIGCHLD handler to clean up zombie processes
void sigchld_handler(int sig) {
    (void)sig; // suppress unused parameter warning
    pid_t pid;
    while ( (pid = waitpid(-1, NULL, WNOHANG)) > 0 ) {
        // Child process cleaned up successfully
    }
    if ( pid < 0 && errno != ECHILD ) {
        perror("waitpid in sigchld_handler");
    }
}

// Handle ACK response from client
int recv_ack(int sockfd, uint16_t expected_block) {
    tftp_ack_t ack_packet;
    struct sockaddr_in ack_addr;
    socklen_t ack_len = sizeof(ack_addr);
    
    printf("Waiting for ACK for block %d...\n", expected_block);
    
    ssize_t ack_received = recvfrom(sockfd, &ack_packet, sizeof(ack_packet), 0,
                                   (struct sockaddr*)&ack_addr, &ack_len);
    
    if ( ack_received < 0 ) {
        perror("recvfrom ACK");
        return -1;
    }
    
    if ( ack_received != sizeof(tftp_ack_t) ) {
        printf("Error: Invalid ACK packet size (%zd bytes, expected %zu)\n", 
               ack_received, sizeof(tftp_ack_t));
        return -1;
    }
    
    // Convert network byte order
    uint16_t ack_opcode = ntohs(ack_packet.opcode);
    uint16_t ack_block = ntohs(ack_packet.block);
    
    printf("Received ACK: opcode=%d, block=%d\n", ack_opcode, ack_block);
    
    if ( ack_opcode != ACK ) {
        printf("Error: Expected ACK opcode, got %d\n", ack_opcode);
        return -1;
    }
    
    if ( ack_block != expected_block ) {
        printf("Error: Expected block %d, got %d\n", expected_block, ack_block);
        return -1;
    }
    
    printf("ACK for block %d confirmed\n", expected_block);
    return 0;
}

// Send ACK packet to client
int send_ack(int sockfd, struct sockaddr_in* cliaddr, uint16_t block_num) {
    tftp_ack_t ack_packet;
    ack_packet.opcode = htons(ACK);
    ack_packet.block = htons(block_num);
    
    ssize_t sent = sendto(sockfd, &ack_packet, sizeof(ack_packet), 0, 
                         (struct sockaddr*)cliaddr, sizeof(*cliaddr));
    
    if ( sent < 0 ) {
        perror("sendto ACK");
        return -1;
    }
    if ( sent != sizeof(ack_packet) ) {
        printf("Warning: Only sent %zd of %zu ACK bytes\n", sent, sizeof(ack_packet));
    }
    
    return 0;
}

void handle_read(char* buffer, int sockfd, struct sockaddr_in* cliaddr) {
    FILE* file = NULL;
    
    // Parse RRQ request: [opcode][filename][\0][mode][\0]
    char* filename = buffer + 2;  // Skip opcode
    char* mode = filename + strlen(filename) + 1;  // Skip filename and null
    
    // printf("RRQ request: filename='%s', mode='%s'\n", filename, mode);
    // printf("Buffer length: %zd bytes\n", n);
    // printf("Raw buffer: ");
    // for (int i = 0; i < n && i < 50; i++) {
    //     printf("%c", buffer[i]);
    // }
    // printf("\n");
    
    // Validate mode
    if ( strcmp(mode, "octet") != 0 ) {
        printf("Error: Only octet mode supported, got '%s'\n", mode);
        tftp_error_t error;
        error.opcode = htons(ERROR);
        error.error_code = htons(ERR_ILLEGAL_OPERATION);
        strcpy(error.error_msg, "Only octet mode supported");
        sendto(sockfd, &error, sizeof(error), 0, 
               (struct sockaddr*)cliaddr, sizeof(*cliaddr));
        return;
    }
    
    // Create file path
    char file_path[512];
    snprintf(file_path, sizeof(file_path), "%s%s", TFTP_BASE_DIR, filename);
    printf("Opening file: %s\n", file_path);
    
    // Open file for reading
    file = fopen(file_path, "rb");
    if ( file == NULL ) {
        printf("Error: File not found\n");
        tftp_error_t error;
        error.opcode = htons(ERROR);
        error.error_code = htons(ERR_FILE_NOT_FOUND);
        strcpy(error.error_msg, "File not found");
        sendto(sockfd, &error, sizeof(error), 0, 
               (struct sockaddr*)cliaddr, sizeof(*cliaddr));
        return;
    }
    
    // Send file in DATA packets
    uint16_t block_num = 1;
    char data[512];
    size_t bytes_read;
    
    printf("Starting file transfer...\n");
    
    do {
        // Read data from file
        bytes_read = fread(data, 1, 512, file);
        if ( ferror(file) ) {
            perror("fread");
            break;
        }
        
        // Create DATA packet
        tftp_data_t data_packet;
        data_packet.opcode = htons(DATA);
        data_packet.block = htons(block_num);
        memcpy(data_packet.data, data, bytes_read);
        
        // Send DATA packet
        size_t packet_size = 4 + bytes_read;  // opcode(2) + block(2) + data
        sendto(sockfd, &data_packet, packet_size, 0,
                             (struct sockaddr*)cliaddr, sizeof(*cliaddr));
        
        
        printf("Sent DATA block %d (%zu bytes)\n", block_num, bytes_read);
        
        // Wait for ACK 
        if ( recv_ack(sockfd, block_num) != 0 ) {
            printf("Error: ACK handling failed for block %d\n", block_num);
            break;
        }
        
        block_num++;
        
    } while ( bytes_read == 512 );  // Continue if we read a full 512-byte block
    
    // Close file before returning
    if ( file ) { fclose(file); }
    printf("File transfer completed\n");
    return;
}

void handle_write(char* buffer, int sockfd, struct sockaddr_in* cliaddr) {
    FILE* file = NULL;
    
    // Parse WRQ request: [opcode][filename][\0][mode][\0]
    char* filename = buffer + 2;  // Skip opcode
    char* mode = filename + strlen(filename) + 1;  // Skip filename and null
    
    // Validate mode
    if ( strcmp(mode, "octet") != 0 ) {
        printf("Error: Only octet mode supported, got '%s'\n", mode);
        tftp_error_t error;
        error.opcode = htons(ERROR);
        error.error_code = htons(ERR_ILLEGAL_OPERATION);
        strcpy(error.error_msg, "Only octet mode supported");
        sendto(sockfd, &error, sizeof(error), 0, 
               (struct sockaddr*)cliaddr, sizeof(*cliaddr));
        return;
    }

    // Create file path
    char file_path[512];
    snprintf(file_path, sizeof(file_path), "%s%s", TFTP_BASE_DIR, filename);
    printf("Creating file: %s\n", file_path);

    // Create file
    file = fopen(file_path, "wb");
    if ( file == NULL ) {
        printf("Error: Failed to create file\n");
        tftp_error_t error;
        error.opcode = htons(ERROR);
        error.error_code = htons(ERR_ACCESS_VIOLATION);
        strcpy(error.error_msg, "Failed to create file");
        sendto(sockfd, &error, sizeof(error), 0, 
               (struct sockaddr*)cliaddr, sizeof(*cliaddr));
        return;
    }

    // Send ACK for block 0 to acknowledge WRQ
    printf("Sending ACK for block 0 to acknowledge WRQ\n");
    if ( send_ack(sockfd, cliaddr, 0) < 0 ) {
        perror("sendto ACK 0");
        fclose(file);
        return;
    }

    // Now wait for DATA packets starting with block 1
    uint16_t expected_block = 1;
    size_t bytes_received;

    printf("Waiting for DATA packets starting with block 1...\n");

    do {
        // Receive DATA packet
        tftp_data_t data_packet;
        struct sockaddr_in from_addr;
        socklen_t from_len = sizeof(from_addr);
        
        ssize_t received = recvfrom(sockfd, &data_packet, sizeof(data_packet), 0,
                                   (struct sockaddr*)&from_addr, &from_len);
        
        if ( received < 0 ) {
            perror("recvfrom DATA");
            break;
        }
        
        // Parse DATA packet
        uint16_t data_opcode = ntohs(data_packet.opcode);
        uint16_t data_block = ntohs(data_packet.block);
        bytes_received = received - 4; // Subtract opcode and block size
        
        printf("Received DATA: opcode=%d, block=%d, bytes=%zu\n", 
               data_opcode, data_block, bytes_received);
        
        if ( data_opcode != DATA ) {
            printf("Error: Expected DATA opcode, got %d\n", data_opcode);
            break;
        }
        
        if ( data_block != expected_block ) {
            printf("Error: Expected block %d, got %d\n", expected_block, data_block);
            break;
        }
        
        // Write data to file
        size_t written = fwrite(data_packet.data, 1, bytes_received, file);
        if ( written != bytes_received ) {
            perror("fwrite");
            break;
        }
        if ( ferror(file) ) {
            perror("file write error");
            break;
        }
        printf("Wrote %zu bytes to file\n", bytes_received);
        
        // Send ACK for this block
        printf("Sending ACK for block %d\n", data_block);
        if ( send_ack(sockfd, cliaddr, data_block) < 0 ) {
            perror("sendto ACK");
            break;
        }
        
        expected_block++;
        
    } while ( bytes_received == 512 ); // Continue if we received a full 512-byte block
    
    // Close file before returning
    if ( file ) { fclose(file); }
    
    printf("File transfer completed\n");
    return;
}

void handle_request(char* buffer, int sockfd, struct sockaddr_in* cliaddr) {
    // Parse the request and determine if it's RRQ or WRQ
    uint16_t opcode = ntohs(*(uint16_t*)buffer);
    
    if (opcode == RRQ) {
        handle_read(buffer, sockfd, cliaddr);
    } else if (opcode == WRQ) {
        handle_write(buffer, sockfd, cliaddr);
    } else {
        // Send error response
        tftp_error_t error;
        error.opcode = htons(ERROR);
        error.error_code = htons(ERR_ILLEGAL_OPERATION);
        strcpy(error.error_msg, "Illegal TFTP operation");
        
        sendto(sockfd, &error, sizeof(error), 0, 
               (struct sockaddr*)cliaddr, sizeof(*cliaddr));
    }
}

int main(int argc, char *argv[]) {

    if( argc != 3 ) {
        fprintf(stderr, "usage:\n\t%s [start of port range] [end of port range]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    int					sockfd;
	struct sockaddr_in	servaddr, cliaddr;

    uint16_t start_port = atoi(argv[1]);
    uint16_t end_port = atoi(argv[2]);
    
    // Validate port range
    if ( start_port < 1 || end_port < 1 ) {
        fprintf(stderr, "Port numbers must be between 1 and 65535\n");
        exit(EXIT_FAILURE);
    }
    
    if ( start_port > end_port ) {
        fprintf(stderr, "Start port must be less than or equal to end port\n");
        exit(EXIT_FAILURE);
    }
    
    // Set up SIGCHLD handler to clean up zombie processes
    if ( signal(SIGCHLD, sigchld_handler) == SIG_ERR ) {
        perror("signal");
        exit(EXIT_FAILURE);
    }
    
    // Create base directory if it doesn't exist
    if (mkdir(TFTP_BASE_DIR, 0755) != 0 && errno != EEXIST) {
        perror("mkdir");
        exit(EXIT_FAILURE);
    }

	// Create UDP socket
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if ( sockfd < 0 ) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	// Set up server address (listen on any interface, start_port)
	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family      = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port        = htons(start_port);
	
	// Bind socket to port
	if ( bind(sockfd, (struct sockaddr *) &servaddr, sizeof(servaddr)) < 0 ) {
		perror("bind");
		close(sockfd);
		exit(EXIT_FAILURE);
	}
	
	printf("TFTP server listening on port %d\n", start_port);

    uint16_t tid_port = start_port;

    // Infinite server loop
    for( ; ; ) {
        socklen_t len = sizeof(cliaddr);
        ssize_t n;
        char buffer[1024];
        
        // Receive TFTP request
        n = recvfrom(sockfd, buffer, sizeof(buffer), 0, 
                     (struct sockaddr *)&cliaddr, &len);
        if ( n < 0 ) {
            if ( errno == EINTR ) {
                // Interrupted by SIGCHLD handler - continue listening
                continue;
            } else {
                perror("recvfrom");
                continue;
            }
        }
        
        uint16_t next_tid_port = tid_port + 1;
        
        // Check if we have available ports before forking
        if ( next_tid_port > end_port ) {
            fprintf(stderr, "Error: All ports in range [%d-%d] have been used\n", 
                    start_port + 1, end_port);
            tftp_error_t error;
            error.opcode = htons(ERROR);
            error.error_code = htons(ERR_DISK_FULL);
            strcpy(error.error_msg, "All ports in range have been used");
            sendto(sockfd, &error, sizeof(error), 0, 
                (struct sockaddr*)&cliaddr, sizeof(cliaddr));
            continue;
        }
        
        // Fork to handle each request
        pid_t pid = fork();
        if ( pid == 0 ) {
            // Child process - handle the request
            close(sockfd); // Close parent's socket
            
            // Use the next available TID port
            uint16_t child_tid_port = next_tid_port;
            printf("Forked child process with TID: %d\n", child_tid_port);
            
            // Create new socket for this connection
            int tid_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
            if ( tid_sockfd < 0 ) {
                perror("socket in child");
                exit(EXIT_FAILURE);
            }
            
            // Bind to TID port
            struct sockaddr_in tid_addr;
            bzero(&tid_addr, sizeof(tid_addr));
            tid_addr.sin_family = AF_INET;
            tid_addr.sin_addr.s_addr = htonl(INADDR_ANY);
            tid_addr.sin_port = htons(child_tid_port);
            
            if ( bind(tid_sockfd, (struct sockaddr *)&tid_addr, sizeof(tid_addr)) < 0 ) {
                perror("bind in child");
                close(tid_sockfd);
                exit(EXIT_FAILURE);
            }
            
            // Handle the TFTP request
            handle_request(buffer, tid_sockfd, &cliaddr);
            
            close(tid_sockfd);
            exit(EXIT_SUCCESS);
        } else if ( pid > 0 ) {
            // Parent process - increment port for next request
            tid_port = next_tid_port;
        } else {
            perror("fork");
        }
    }

    close(sockfd);
    printf("Server shutting down\n");
    exit(EXIT_SUCCESS);
}
