#!/bin/bash
# EndpointSecurity Multi-Version Build Script
# This script builds osquery with EndpointSecurity for multiple macOS versions

set -e

# Root directory for builds
ROOT_DIR=$(pwd)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Check if we're in the osquery repository root
if [ ! -f "CMakeLists.txt" ]; then
  echo "Error: This script must be run from the osquery repository root"
  exit 1
fi

# Create base build directories
mkdir -p build-logs

# Define macOS versions to build for
build_for_versions() {
  # macOS 10.15 (Catalina)
  build_for_version "10.15" "build-es-10.15"
  
  # macOS 11.0 (Big Sur)
  build_for_version "11.0" "build-es-11"
  
  # macOS 12.0 (Monterey)
  build_for_version "12.0" "build-es-12"
  
  # macOS 13.0 (Ventura)
  build_for_version "13.0" "build-es-13"
  
  # macOS 14.0 (Sonoma)
  build_for_version "14.0" "build-es-14"
  
  # macOS 15.0
  build_for_version "15.0" "build-es-15"
}

# Build for a specific macOS version
build_for_version() {
  local version="$1"
  local build_dir="$2"
  local log_file="build-logs/build-macos-${version}.log"
  
  echo "Building for macOS $version in $build_dir..."
  
  # Create build directory
  mkdir -p "$build_dir"
  cd "$build_dir"
  
  # Configure with CMake
  echo "Configuring with CMake..."
  cmake -DCMAKE_OSX_DEPLOYMENT_TARGET=$version -DCMAKE_BUILD_TYPE=Debug .. > "$ROOT_DIR/$log_file" 2>&1
  
  # Build
  echo "Building..."
  make -j$(sysctl -n hw.ncpu) >> "$ROOT_DIR/$log_file" 2>&1
  
  # Return to root directory
  cd "$ROOT_DIR"
  
  echo "Build for macOS $version completed"
  echo "Log file: $log_file"
}

# Verify all builds
verify_builds() {
  echo "Verifying builds..."
  
  for build_dir in build-es-*; do
    if [ -d "$build_dir" ]; then
      echo "Checking $build_dir..."
      
      # Check if osqueryi exists
      if [ -f "$build_dir/osqueryi" ]; then
        echo "✅ $build_dir/osqueryi exists"
        
        # Try to run osqueryi
        if [ -x "$build_dir/osqueryi" ]; then
          version_output=$("$build_dir/osqueryi" --version)
          echo "   $version_output"
        else
          echo "❌ $build_dir/osqueryi is not executable"
        fi
      else
        echo "❌ $build_dir/osqueryi does not exist"
      fi
      
      echo ""
    fi
  done
}

# Sign all binaries with entitlements
sign_binaries() {
  echo "Signing binaries with EndpointSecurity entitlements..."
  
  # Check if entitlements file exists
  if [ ! -f "$SCRIPT_DIR/es_entitlements.xml" ]; then
    echo "Error: Entitlements file not found at $SCRIPT_DIR/es_entitlements.xml"
    return 1
  fi
  
  for build_dir in build-es-*; do
    if [ -d "$build_dir" ]; then
      echo "Signing binaries in $build_dir..."
      
      # Sign osqueryi
      if [ -f "$build_dir/osqueryi" ]; then
        echo "Signing $build_dir/osqueryi..."
        codesign --force --sign - --entitlements "$SCRIPT_DIR/es_entitlements.xml" "$build_dir/osqueryi"
        
        # Verify signature
        codesign -vvv "$build_dir/osqueryi"
        
        # Check entitlements
        echo "Checking entitlements..."
        codesign -d --entitlements - "$build_dir/osqueryi" | grep -q "com.apple.developer.endpoint-security.client" && echo "✅ EndpointSecurity entitlement found" || echo "❌ EndpointSecurity entitlement not found"
      fi
      
      # Sign osqueryd
      if [ -f "$build_dir/osqueryd" ]; then
        echo "Signing $build_dir/osqueryd..."
        codesign --force --sign - --entitlements "$SCRIPT_DIR/es_entitlements.xml" "$build_dir/osqueryd"
        
        # Verify signature
        codesign -vvv "$build_dir/osqueryd"
      fi
      
      echo "Signing completed for $build_dir"
      echo ""
    fi
  done
}

# Run tests for each build
run_tests() {
  echo "Running tests for each build..."
  
  # Ensure test script exists
  if [ ! -f "$SCRIPT_DIR/test_es_cross_version.sh" ]; then
    echo "Error: Test script not found at $SCRIPT_DIR/test_es_cross_version.sh"
    return 1
  fi
  
  # Get current macOS version
  MACOS_VERSION=$(sw_vers -productVersion | cut -d. -f1)
  
  # Only run tests for builds compatible with current macOS
  for build_dir in build-es-*; do
    if [ -d "$build_dir" ]; then
      # Extract version from build directory
      BUILD_VERSION=$(echo "$build_dir" | sed -E 's/.*-es-([0-9]+).*$/\1/g')
      
      # Compare versions
      if [ -z "$BUILD_VERSION" ] || [ "$BUILD_VERSION" -gt "$MACOS_VERSION" ]; then
        echo "Skipping tests for $build_dir (requires macOS $BUILD_VERSION+, current: $MACOS_VERSION)"
        continue
      fi
      
      echo "Running tests for $build_dir..."
      
      # Create a copy of the test script in the build directory
      cp "$SCRIPT_DIR/test_es_cross_version.sh" "$build_dir/"
      chmod +x "$build_dir/test_es_cross_version.sh"
      
      # Run test script
      cd "$build_dir"
      ./test_es_cross_version.sh
      cd "$ROOT_DIR"
      
      echo "Tests completed for $build_dir"
      echo ""
    fi
  done
}

# Display help
show_help() {
  echo "EndpointSecurity Multi-Version Build Script"
  echo "Usage: $0 [options]"
  echo ""
  echo "Options:"
  echo "  --help          Show this help message"
  echo "  --build         Build for all macOS versions"
  echo "  --verify        Verify all builds"
  echo "  --sign          Sign all binaries with EndpointSecurity entitlements"
  echo "  --test          Run tests for each compatible build"
  echo "  --all           Build, verify, sign, and test all versions"
  echo "  --version=X.Y   Build only for macOS X.Y"
  echo ""
  echo "Examples:"
  echo "  $0 --build            Build for all macOS versions"
  echo "  $0 --build --sign     Build and sign for all macOS versions"
  echo "  $0 --version=14.0     Build only for macOS 14.0"
  echo "  $0 --all              Build, verify, sign, and test all versions"
}

# Parse arguments
if [ $# -eq 0 ]; then
  show_help
  exit 0
fi

DO_BUILD=false
DO_VERIFY=false
DO_SIGN=false
DO_TEST=false
SPECIFIC_VERSION=""

for arg in "$@"; do
  case $arg in
    --help)
      show_help
      exit 0
      ;;
    --build)
      DO_BUILD=true
      ;;
    --verify)
      DO_VERIFY=true
      ;;
    --sign)
      DO_SIGN=true
      ;;
    --test)
      DO_TEST=true
      ;;
    --all)
      DO_BUILD=true
      DO_VERIFY=true
      DO_SIGN=true
      DO_TEST=true
      ;;
    --version=*)
      SPECIFIC_VERSION="${arg#*=}"
      DO_BUILD=true
      ;;
    *)
      echo "Unknown option: $arg"
      show_help
      exit 1
      ;;
  esac
done

# Main execution
echo "EndpointSecurity Multi-Version Build Script"
echo "----------------------------------------"

# Build for specific version if specified
if [ -n "$SPECIFIC_VERSION" ]; then
  echo "Building only for macOS $SPECIFIC_VERSION"
  build_for_version "$SPECIFIC_VERSION" "build-es-${SPECIFIC_VERSION/./}"
  
  if [ "$DO_VERIFY" = true ]; then
    echo "Verifying build for macOS $SPECIFIC_VERSION..."
    # Check if osqueryi exists
    build_dir="build-es-${SPECIFIC_VERSION/./}"
    if [ -f "$build_dir/osqueryi" ]; then
      echo "✅ $build_dir/osqueryi exists"
      
      # Try to run osqueryi
      if [ -x "$build_dir/osqueryi" ]; then
        version_output=$("$build_dir/osqueryi" --version)
        echo "   $version_output"
      else
        echo "❌ $build_dir/osqueryi is not executable"
      fi
    else
      echo "❌ $build_dir/osqueryi does not exist"
    fi
  fi
  
  if [ "$DO_SIGN" = true ]; then
    echo "Signing build for macOS $SPECIFIC_VERSION..."
    build_dir="build-es-${SPECIFIC_VERSION/./}"
    if [ -f "$build_dir/osqueryi" ]; then
      echo "Signing $build_dir/osqueryi..."
      codesign --force --sign - --entitlements "$SCRIPT_DIR/es_entitlements.xml" "$build_dir/osqueryi"
      
      # Verify signature
      codesign -vvv "$build_dir/osqueryi"
      
      # Check entitlements
      echo "Checking entitlements..."
      codesign -d --entitlements - "$build_dir/osqueryi" | grep -q "com.apple.developer.endpoint-security.client" && echo "✅ EndpointSecurity entitlement found" || echo "❌ EndpointSecurity entitlement not found"
    fi
  fi
  
  if [ "$DO_TEST" = true ]; then
    echo "Testing build for macOS $SPECIFIC_VERSION..."
    build_dir="build-es-${SPECIFIC_VERSION/./}"
    
    # Create a copy of the test script in the build directory
    cp "$SCRIPT_DIR/test_es_cross_version.sh" "$build_dir/"
    chmod +x "$build_dir/test_es_cross_version.sh"
    
    # Run test script
    cd "$build_dir"
    ./test_es_cross_version.sh
    cd "$ROOT_DIR"
  fi
else
  # Execute requested operations
  if [ "$DO_BUILD" = true ]; then
    build_for_versions
  fi
  
  if [ "$DO_VERIFY" = true ]; then
    verify_builds
  fi
  
  if [ "$DO_SIGN" = true ]; then
    sign_binaries
  fi
  
  if [ "$DO_TEST" = true ]; then
    run_tests
  fi
fi

echo "Script completed successfully"