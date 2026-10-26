#!/bin/bash
# Cyber Threat Engine Double-Click Launcher for macOS
# Changes to the build directory and runs the interactive ThreatEngine
cd "$(dirname "$0")/build" || exit 1

# If the binary isn't built yet, build it automatically
if [ ! -f "./ThreatEngine" ]; then
    echo "ThreatEngine binary not found. Compiling now..."
    cmake .. && make
fi

# Clear screen and launch
clear
./ThreatEngine
EOF
