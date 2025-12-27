#!/bin/bash

# Server Log Forensics Tool - Auto Start Script
# Usage: ./startup.sh [mode]

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PORT=5000
LOG_DIR="/var/log"
REPORT_DIR="./reports"
DASHBOARD_URL="http://localhost:$PORT"

# Functions
print_header() {
    echo -e "${BLUE}"
    echo "================================================"
    echo "🔐 SERVER LOG FORENSICS TOOL"
    echo "================================================"
    echo -e "${NC}"
}

print_status() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

check_dependencies() {
    print_status "Checking dependencies..."
    
    # Check Python
    if ! command -v python3 &> /dev/null; then
        print_error "Python3 is not installed"
        exit 1
    fi
    
    # Check pip
    if ! command -v pip3 &> /dev/null; then
        print_error "pip3 is not installed"
        exit 1
    fi
    
    # Check Python packages
    for package in flask pandas plotly; do
        if ! python3 -c "import $package" 2>/dev/null; then
            print_warning "Installing missing package: $package"
            pip3 install $package
        fi
    done
    
    print_status "All dependencies are satisfied"
}

check_port() {
    if netstat -tuln 2>/dev/null | grep -q ":$PORT "; then
        return 0  # Port is in use
    else
        return 1  # Port is free
    fi
}

start_dashboard() {
    print_status "Starting web dashboard on port $PORT..."
    
    # Check if port is available
    if check_port; then
        print_warning "Port $PORT is already in use"
        read -p "Kill process on port $PORT? (y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            fuser -k $PORT/tcp 2>/dev/null
            sleep 2
        else
            print_error "Cannot start dashboard. Port $PORT is busy."
            return 1
        fi
    fi
    
    # Start dashboard in background
    python3 dashboard/app.py > dashboard.log 2>&1 &
    DASHBOARD_PID=$!
    echo $DASHBOARD_PID > dashboard.pid
    
    # Wait for dashboard to start
    print_status "Waiting for dashboard to initialize..."
    for i in {1..30}; do
        if curl -s "http://localhost:$PORT" > /dev/null 2>&1; then
            print_status "Dashboard started successfully!"
            print_status "PID: $DASHBOARD_PID"
            print_status "Logs: dashboard.log"
            return 0
        fi
        sleep 1
        echo -n "."
    done
    
    print_error "Dashboard failed to start"
    return 1
}

start_cli() {
    print_status "Starting CLI interface..."
    echo -e "${YELLOW}"
    echo "================================================"
    echo "CLI INTERFACE (Press Ctrl+C to return to menu)"
    echo "================================================"
    echo -e "${NC}"
    
    python3 main.py "$@"
}

run_analysis() {
    print_status "Running analysis on: $LOG_DIR"
    
    # Create reports directory if it doesn't exist
    mkdir -p "$REPORT_DIR"
    
    # Run analysis
    python3 main.py analyze \
        --log-dir "$LOG_DIR" \
        --output "$REPORT_DIR" \
        --time-range "24h" \
        --verbose
    
    print_status "Analysis complete! Reports saved to: $REPORT_DIR"
}

open_browser() {
    print_status "Opening dashboard in browser..."
    
    # Try different browser opening commands
    if command -v xdg-open &> /dev/null; then
        xdg-open "$DASHBOARD_URL" &
    elif command -v open &> /dev/null; then
        open "$DASHBOARD_URL" &
    elif command -v start &> /dev/null; then
        start "$DASHBOARD_URL" &
    else
        print_warning "Could not open browser automatically"
        print_status "Please open manually: $DASHBOARD_URL"
    fi
}

show_menu() {
    echo -e "\n${BLUE}SELECT MODE:${NC}"
    echo "1) Dashboard + CLI (Recommended)"
    echo "2) Dashboard only"
    echo "3) CLI only"
    echo "4) Automatic Analysis + Dashboard"
    echo "5) System Service Mode"
    echo "6) Exit"
    echo -e "${YELLOW}"
    read -p "Enter choice [1-6]: " -n 1 -r
    echo -e "${NC}"
}

cleanup() {
    print_status "Cleaning up..."
    
    # Kill dashboard if running
    if [ -f dashboard.pid ]; then
        PID=$(cat dashboard.pid)
        if kill -0 $PID 2>/dev/null; then
            print_status "Stopping dashboard (PID: $PID)"
            kill $PID
        fi
        rm -f dashboard.pid
    fi
    
    print_status "Cleanup complete"
}

# Main execution
main() {
    print_header
    check_dependencies
    
    trap cleanup EXIT INT TERM
    
    MODE=${1:-""}
    
    case $MODE in
        "dashboard")
            start_dashboard
            open_browser
            wait
            ;;
        "cli")
            start_cli "${@:2}"
            ;;
        "auto")
            start_dashboard && run_analysis && open_browser
            wait
            ;;
        "service")
            start_dashboard
            # Keep running as service
            print_status "Running as system service..."
            print_status "Dashboard URL: $DASHBOARD_URL"
            print_status "Press Ctrl+C to stop"
            wait
            ;;
        *)
            # Interactive mode
            while true; do
                show_menu
                case $REPLY in
                    1)
                        if start_dashboard; then
                            open_browser
                            start_cli
                        fi
                        ;;
                    2)
                        if start_dashboard; then
                            open_browser
                            print_status "Dashboard running. Press Ctrl+C to stop."
                            wait
                        fi
                        ;;
                    3)
                        start_cli
                        ;;
                    4)
                        if start_dashboard; then
                            run_analysis
                            open_browser
                            print_status "System running. Press Ctrl+C to stop."
                            wait
                        fi
                        ;;
                    5)
                        if start_dashboard; then
                            print_status "Running as system service..."
                            print_status "Dashboard URL: $DASHBOARD_URL"
                            print_status "Press Ctrl+C to stop"
                            wait
                        fi
                        ;;
                    6)
                        print_status "Exiting..."
                        exit 0
                        ;;
                    *)
                        print_error "Invalid choice"
                        ;;
                esac
            done
            ;;
    esac
}

# Run main function
main "$@"
