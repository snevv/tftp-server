TFTP Server Implementation
========================

This is a TFTP server implementation according to RFC 1350.

Features:
- Supports "octet" mode only (no "netascii" or "mail" mode)
- Multiple concurrent connections using fork()
- Timeout handling using SIGALRM (1s retransmit, 10s abort)
- Port range management for TIDs
- Prevents Sorcerer's Apprentice Syndrome

Usage:
    ./tftp.out [start_port] [end_port]

Example:
    ./tftp.out 2000 2010

The server will listen on the start_port and use subsequent ports
in the range for TIDs (Transfer IDs).

Port Management:
- Server listens on start_port
- Each new connection uses the next available port in the range
- Once all ports in the range are used, the server refuses new connections

Testing:
- Use a TFTP client in binary mode
- Test with files smaller than 32MB
- Ubuntu/WSL: sudo apt install tftp

Implementation Notes:
- Uses SIGALRM for timeout handling as required
- Fork() for concurrent connections
- Proper network byte order conversion
- Error handling for all system calls
