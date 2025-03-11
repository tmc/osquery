#!/bin/bash
# EndpointSecurity Version Identifier Script
# This script helps identify which EndpointSecurity features are available on the current macOS version

set -e

# Detect macOS version
MACOS_VERSION=$(sw_vers -productVersion | cut -d. -f1)
MACOS_MINOR=$(sw_vers -productVersion | cut -d. -f2)
MACOS_FULL=$(sw_vers -productVersion)
echo "Detected macOS version: $MACOS_FULL (Major: $MACOS_VERSION, Minor: $MACOS_MINOR)"

# Define feature sets by version
define_features() {
  # Base features available in macOS 10.15 (Catalina)
  BASE_FEATURES=(
    "process_exec"
    "process_fork"
    "process_exit"
    "file_create"
    "file_open"
    "file_close"
    "file_rename"
    "file_unlink"
    "file_write"
    "network_unix_socket"
  )
  
  # Features added in macOS 11.0 (Big Sur)
  BIGSUR_FEATURES=(
    "memory_mmap"
    "memory_mprotect"
    "file_acl"
    "file_extended_attrs"
  )
  
  # Features added in macOS 12.0 (Monterey)
  MONTEREY_FEATURES=(
    "uid_operations"
    "gid_operations"
    "remote_thread"
  )
  
  # Features added in macOS 13.0 (Ventura)
  VENTURA_FEATURES=(
    "authentication"
    "malware_detection"
    "openssh_login"
    "screensharing"
    "loginwindow_sessions"
  )
  
  # Features added in macOS 14.0 (Sonoma)
  SONOMA_FEATURES=(
    "xpc_events"
    "profile_events"
    "su_sudo_events"
    "opendirectory_events"
  )
  
  # Features removed in macOS 15.0
  REMOVED_FEATURES=(
    "network_socket"
    "network_connect"
    "network_bind"
    "network_listen"
    "network_accept"
    "file_chmod"
    "file_chown"
    "file_symlink"
    "system_sysctl"
    "system_ptrace"
    "tcc_modify"
  )
}

# Get list of available features for the current macOS version
get_available_features() {
  local available_features=()
  
  # Start with base features (all macOS versions 10.15+)
  available_features+=("${BASE_FEATURES[@]}")
  
  # Add version-specific features
  if [ "$MACOS_VERSION" -ge 11 ]; then
    available_features+=("${BIGSUR_FEATURES[@]}")
  fi
  
  if [ "$MACOS_VERSION" -ge 12 ]; then
    available_features+=("${MONTEREY_FEATURES[@]}")
  fi
  
  if [ "$MACOS_VERSION" -ge 13 ]; then
    available_features+=("${VENTURA_FEATURES[@]}")
  fi
  
  if [ "$MACOS_VERSION" -ge 14 ]; then
    available_features+=("${SONOMA_FEATURES[@]}")
  fi
  
  # Remove features that were removed in macOS 15+
  if [ "$MACOS_VERSION" -ge 15 ]; then
    local final_features=()
    for feature in "${available_features[@]}"; do
      local removed=false
      for removed_feature in "${REMOVED_FEATURES[@]}"; do
        if [ "$feature" = "$removed_feature" ]; then
          removed=true
          break
        fi
      done
      if [ "$removed" = false ]; then
        final_features+=("$feature")
      fi
    done
    available_features=("${final_features[@]}")
  fi
  
  echo "${available_features[@]}"
}

# Check if a specific feature is available
is_feature_available() {
  local feature="$1"
  local available_features=($(get_available_features))
  
  for available in "${available_features[@]}"; do
    if [ "$available" = "$feature" ]; then
      return 0
    fi
  done
  
  return 1
}

# Generate EndpointSecurity feature report
generate_feature_report() {
  local output_file="es_features_report.txt"
  local available_features=($(get_available_features))
  
  echo "EndpointSecurity Feature Availability Report" > "$output_file"
  echo "----------------------------------------" >> "$output_file"
  echo "macOS Version: $MACOS_FULL" >> "$output_file"
  echo "Generated: $(date)" >> "$output_file"
  echo "" >> "$output_file"
  
  echo "Available Features:" >> "$output_file"
  for feature in "${available_features[@]}"; do
    echo "  ✅ $feature" >> "$output_file"
  done
  
  echo "" >> "$output_file"
  echo "Unavailable Features:" >> "$output_file"
  
  # Check all possible features and list unavailable ones
  local all_features=(
    "${BASE_FEATURES[@]}"
    "${BIGSUR_FEATURES[@]}"
    "${MONTEREY_FEATURES[@]}"
    "${VENTURA_FEATURES[@]}"
    "${SONOMA_FEATURES[@]}"
  )
  
  # Remove duplicates
  all_features=($(printf "%s\n" "${all_features[@]}" | sort -u))
  
  for feature in "${all_features[@]}"; do
    if ! is_feature_available "$feature"; then
      echo "  ❌ $feature" >> "$output_file"
    fi
  done
  
  echo "" >> "$output_file"
  echo "Recommended osquery EndpointSecurity flags:" >> "$output_file"
  echo "  --disable_events=false --disable_endpointsecurity=false" >> "$output_file"
  
  # Add version-specific flags
  if [ "$MACOS_VERSION" -ge 11 ]; then
    echo "  --enable_es_memory_events=true" >> "$output_file"
  fi
  
  if [ "$MACOS_VERSION" -ge 12 ]; then
    echo "  --enable_es_system_events=true" >> "$output_file"
  fi
  
  if [ "$MACOS_VERSION" -ge 13 ]; then
    echo "  --enable_es_authentication_events=true" >> "$output_file"
  fi
  
  if [ "$MACOS_VERSION" -ge 14 ]; then
    echo "  --enable_es_xpc_events=true" >> "$output_file"
    echo "  --enable_es_profile_events=true" >> "$output_file"
  fi
  
  echo "" >> "$output_file"
  echo "Report saved to $output_file"
}

# Generate SDK compatibility report
generate_sdk_report() {
  local output_file="es_sdk_report.txt"
  
  echo "EndpointSecurity SDK Compatibility Report" > "$output_file"
  echo "----------------------------------------" >> "$output_file"
  echo "macOS Version: $MACOS_FULL" >> "$output_file"
  echo "Generated: $(date)" >> "$output_file"
  echo "" >> "$output_file"
  
  # Check for the EndpointSecurity header
  if [ -f "/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk/usr/include/EndpointSecurity/EndpointSecurity.h" ]; then
    echo "EndpointSecurity SDK found in Xcode" >> "$output_file"
    
    # Try to extract SDK version from header
    local sdk_header="/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk/usr/include/EndpointSecurity/EndpointSecurity.h"
    local api_version=$(grep -E "ES_API_VERSION = " "$sdk_header" | awk '{print $NF}' | tr -d ";")
    
    if [ -n "$api_version" ]; then
      echo "EndpointSecurity API Version: $api_version" >> "$output_file"
    else
      echo "EndpointSecurity API Version: Unknown" >> "$output_file"
    fi
    
    # Check for specific event types in header
    echo "" >> "$output_file"
    echo "Event Type Availability in SDK:" >> "$output_file"
    
    # List of event types to check
    local event_types=(
      "ES_EVENT_TYPE_NOTIFY_EXEC"
      "ES_EVENT_TYPE_NOTIFY_FORK"
      "ES_EVENT_TYPE_NOTIFY_EXIT"
      "ES_EVENT_TYPE_NOTIFY_MMAP"
      "ES_EVENT_TYPE_NOTIFY_MPROTECT"
      "ES_EVENT_TYPE_NOTIFY_AUTHENTICATION"
      "ES_EVENT_TYPE_NOTIFY_XPC_CONNECT"
      "ES_EVENT_TYPE_NOTIFY_SOCKET"
      "ES_EVENT_TYPE_NOTIFY_CONNECT"
      "ES_EVENT_TYPE_NOTIFY_SOCKET_CREATE"
    )
    
    for event_type in "${event_types[@]}"; do
      if grep -q "$event_type" "$sdk_header"; then
        echo "  ✅ $event_type is defined" >> "$output_file"
      else
        echo "  ❌ $event_type is not defined" >> "$output_file"
      fi
    done
  else
    echo "EndpointSecurity SDK not found in Xcode" >> "$output_file"
  fi
  
  echo "" >> "$output_file"
  echo "Build Recommendations:" >> "$output_file"
  if [ "$MACOS_VERSION" -ge 15 ]; then
    echo "For macOS 15+, build with -DCMAKE_OSX_DEPLOYMENT_TARGET=15.0" >> "$output_file"
    echo "Include compatibility defines for removed event types (see ES_EVENT_TYPE_NOTIFY_SOCKET, etc.)" >> "$output_file"
  elif [ "$MACOS_VERSION" -ge 14 ]; then
    echo "For macOS 14, build with -DCMAKE_OSX_DEPLOYMENT_TARGET=14.0" >> "$output_file"
  elif [ "$MACOS_VERSION" -ge 13 ]; then
    echo "For macOS 13, build with -DCMAKE_OSX_DEPLOYMENT_TARGET=13.0" >> "$output_file"
  elif [ "$MACOS_VERSION" -ge 12 ]; then
    echo "For macOS 12, build with -DCMAKE_OSX_DEPLOYMENT_TARGET=12.0" >> "$output_file"
  elif [ "$MACOS_VERSION" -ge 11 ]; then
    echo "For macOS 11, build with -DCMAKE_OSX_DEPLOYMENT_TARGET=11.0" >> "$output_file"
  else
    echo "For macOS 10.15, build with -DCMAKE_OSX_DEPLOYMENT_TARGET=10.15" >> "$output_file"
  fi
  
  echo "" >> "$output_file"
  echo "Report saved to $output_file"
}

# Main execution
define_features
generate_feature_report
generate_sdk_report

echo "EndpointSecurity analysis completed for macOS $MACOS_FULL"
echo "Feature report saved to es_features_report.txt"
echo "SDK report saved to es_sdk_report.txt"