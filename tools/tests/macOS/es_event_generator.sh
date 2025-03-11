#!/bin/bash
# EndpointSecurity Event Generator Script
# This script generates various EndpointSecurity events for testing

set -e

# Detect macOS version
MACOS_VERSION=$(sw_vers -productVersion | cut -d. -f1)
echo "Detected macOS version: $MACOS_VERSION"

# Output directory for logs
LOG_DIR="es_event_logs"
mkdir -p "$LOG_DIR"

# Generate process events (works on all macOS versions 10.15+)
generate_process_events() {
  echo "Generating process events..."
  
  # Execute some commands to generate exec events
  echo "Executing commands to generate process events..."
  echo "Hello world" > "$LOG_DIR/test.txt"
  ls -la > "$LOG_DIR/ls_output.txt"
  find . -name "*.sh" -type f | head -5 > "$LOG_DIR/find_output.txt"
  
  # Fork some processes
  for i in {1..3}; do
    (sleep 1; echo "Forked process $i" >> "$LOG_DIR/fork_output.txt") &
  done
  
  echo "Process events generated"
}

# Generate file events (works on all macOS versions 10.15+)
generate_file_events() {
  echo "Generating file events..."
  
  # Create test directory
  mkdir -p "$LOG_DIR/file_events"
  cd "$LOG_DIR/file_events"
  
  # Create files
  echo "Creating files..."
  echo "Test file 1" > test1.txt
  echo "Test file 2" > test2.txt
  echo "Test file 3" > test3.txt
  
  # Modify files
  echo "Modifying files..."
  echo "Modified content" >> test1.txt
  echo "More content" >> test2.txt
  
  # Rename files
  echo "Renaming files..."
  mv test3.txt test3_renamed.txt
  
  # Change permissions
  echo "Changing permissions..."
  chmod 644 test1.txt
  chmod 600 test2.txt
  
  # Delete files
  echo "Deleting files..."
  rm test3_renamed.txt
  
  cd ../..
  echo "File events generated"
}

# Generate network events (works on all macOS versions 10.15+, limited in 15+)
generate_network_events() {
  echo "Generating network events..."
  
  # Basic socket operations
  echo "Performing network operations..."
  ping -c 3 localhost > "$LOG_DIR/ping_output.txt"
  
  # HTTP request
  curl -s https://example.com > "$LOG_DIR/curl_output.txt"
  
  # Unix domain socket operations (works in macOS 15+)
  echo "Testing Unix domain socket operations..."
  SOCKET_PATH="$LOG_DIR/test.sock"
  nc -l -U "$SOCKET_PATH" > "$LOG_DIR/socket_server.txt" 2>&1 &
  SERVER_PID=$!
  sleep 1
  echo "Test message" | nc -U "$SOCKET_PATH" > "$LOG_DIR/socket_client.txt" 2>&1
  kill $SERVER_PID 2>/dev/null || true
  
  echo "Network events generated"
}

# Generate memory protection events (macOS 11.0+)
generate_memory_events() {
  if [ "$MACOS_VERSION" -lt 11 ]; then
    echo "Skipping memory events (requires macOS 11.0+)"
    return 0
  fi
  
  echo "Generating memory protection events..."
  
  # Run a simple program that does mmap and mprotect operations
  cat > "$LOG_DIR/memory_test.c" << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

int main() {
  // mmap a region of memory
  void *addr = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (addr == MAP_FAILED) {
    perror("mmap");
    return 1;
  }
  
  // Write to the memory
  sprintf(addr, "Hello, mmap!");
  printf("Wrote to mmap: %s\n", (char*)addr);
  
  // Change protection to read-only
  if (mprotect(addr, 4096, PROT_READ) != 0) {
    perror("mprotect");
    return 1;
  }
  
  // Read from the memory
  printf("Read from mmap: %s\n", (char*)addr);
  
  // Unmap the memory
  if (munmap(addr, 4096) != 0) {
    perror("munmap");
    return 1;
  }
  
  return 0;
}
EOF
  
  # Compile and run
  cc -o "$LOG_DIR/memory_test" "$LOG_DIR/memory_test.c"
  "$LOG_DIR/memory_test" > "$LOG_DIR/memory_test_output.txt" 2>&1
  
  echo "Memory protection events generated"
}

# Generate authentication events (macOS 13.0+)
generate_auth_events() {
  if [ "$MACOS_VERSION" -lt 13 ]; then
    echo "Skipping authentication events (requires macOS 13.0+)"
    return 0
  fi
  
  echo "Generating authentication events..."
  
  # Note: Most authentication events require actual user interaction
  # or sudo/administrative privileges to generate
  
  # Try to use the 'security' command to trigger auth events
  security find-generic-password -s "osquery-test" -a "test-account" 2>/dev/null || true
  
  # Create a temp account credentials file
  echo "test:password" > "$LOG_DIR/test_creds.txt"
  
  # Attempt a sudo command (will fail without user interaction, but will generate events)
  sudo -k # Reset sudo timestamp
  sudo -n echo "Testing sudo" > "$LOG_DIR/sudo_output.txt" 2>&1 || true
  
  echo "Authentication events attempted"
}

# Generate XPC events (macOS 14.0+)
generate_xpc_events() {
  if [ "$MACOS_VERSION" -lt 14 ]; then
    echo "Skipping XPC events (requires macOS 14.0+)"
    return 0
  fi
  
  echo "Generating XPC events..."
  
  # Use system commands that trigger XPC connections
  defaults read com.apple.finder > "$LOG_DIR/defaults_output.txt" 2>&1
  system_profiler SPSoftwareDataType > "$LOG_DIR/system_profiler_output.txt" 2>&1
  
  echo "XPC events generated"
}

# Run event generators based on macOS version
run_all_generators() {
  echo "Starting EndpointSecurity event generation for macOS $MACOS_VERSION..."
  echo "Test started at $(date)" > "$LOG_DIR/summary.log"
  echo "macOS version: $MACOS_VERSION" >> "$LOG_DIR/summary.log"
  
  # Run all appropriate generators
  generate_process_events
  generate_file_events
  generate_network_events
  generate_memory_events
  generate_auth_events
  generate_xpc_events
  
  echo "All event generation completed at $(date)"
  echo "Test completed at $(date)" >> "$LOG_DIR/summary.log"
}

# Main execution
run_all_generators
echo "Event generation complete. Logs saved in $LOG_DIR"