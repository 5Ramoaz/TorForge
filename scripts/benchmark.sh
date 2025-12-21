#!/bin/bash
# TorForge Benchmark Script
# Measures performance metrics for transparent Tor proxy

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║           TorForge Performance Benchmark Suite               ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run as root (sudo ./benchmark.sh)${NC}"
    exit 1
fi

# Check dependencies
check_deps() {
    local deps=("curl" "time" "bc")
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            echo -e "${RED}Missing dependency: $dep${NC}"
            exit 1
        fi
    done
}

# Measure startup time
benchmark_startup() {
    echo -e "${YELLOW}[1/5] Measuring startup time...${NC}"
    
    # TorForge startup
    local start=$(date +%s.%N)
    timeout 120 ./build/torforge tor &
    local pid=$!
    
    # Wait for Tor to bootstrap
    while ! curl -s --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip &>/dev/null; do
        sleep 1
    done
    local end=$(date +%s.%N)
    
    local torforge_time=$(echo "$end - $start" | bc)
    echo -e "   TorForge startup: ${GREEN}${torforge_time}s${NC}"
    
    # Kill TorForge
    kill $pid 2>/dev/null || true
    ./build/torforge stop 2>/dev/null || true
    sleep 2
    
    echo ""
}

# Measure throughput
benchmark_throughput() {
    echo -e "${YELLOW}[2/5] Measuring throughput...${NC}"
    
    # Start TorForge
    ./build/torforge tor &
    local pid=$!
    sleep 10
    
    # Download test file through Tor
    local test_url="http://speedtest.tele2.net/1MB.zip"
    local start=$(date +%s.%N)
    curl -sS --socks5-hostname 127.0.0.1:9050 -o /dev/null "$test_url"
    local end=$(date +%s.%N)
    
    local time=$(echo "$end - $start" | bc)
    local speed=$(echo "scale=2; 1 / $time" | bc)
    echo -e "   1MB download: ${GREEN}${time}s (${speed} MB/s)${NC}"
    
    # Cleanup
    kill $pid 2>/dev/null || true
    ./build/torforge stop 2>/dev/null || true
    sleep 2
    
    echo ""
}

# Measure latency
benchmark_latency() {
    echo -e "${YELLOW}[3/5] Measuring latency...${NC}"
    
    # Start TorForge
    ./build/torforge tor &
    local pid=$!
    sleep 10
    
    # Measure multiple requests
    local total=0
    local count=5
    
    for i in $(seq 1 $count); do
        local start=$(date +%s.%N)
        curl -sS --socks5-hostname 127.0.0.1:9050 -o /dev/null https://www.torproject.org/
        local end=$(date +%s.%N)
        local latency=$(echo "($end - $start) * 1000" | bc)
        total=$(echo "$total + $latency" | bc)
    done
    
    local avg=$(echo "scale=0; $total / $count" | bc)
    echo -e "   Average latency: ${GREEN}${avg}ms${NC}"
    
    # Cleanup
    kill $pid 2>/dev/null || true
    ./build/torforge stop 2>/dev/null || true
    sleep 2
    
    echo ""
}

# Measure memory usage
benchmark_memory() {
    echo -e "${YELLOW}[4/5] Measuring memory usage...${NC}"
    
    # Start TorForge
    ./build/torforge tor &
    local pid=$!
    sleep 15
    
    # Get memory usage
    local mem=$(ps -p $pid -o rss= 2>/dev/null || echo "0")
    local mem_mb=$(echo "scale=2; $mem / 1024" | bc)
    echo -e "   TorForge memory: ${GREEN}${mem_mb} MB${NC}"
    
    # Get Tor memory
    local tor_pid=$(pgrep -f "^tor" | head -1)
    if [ -n "$tor_pid" ]; then
        local tor_mem=$(ps -p $tor_pid -o rss= 2>/dev/null || echo "0")
        local tor_mem_mb=$(echo "scale=2; $tor_mem / 1024" | bc)
        echo -e "   Tor process memory: ${GREEN}${tor_mem_mb} MB${NC}"
    fi
    
    # Cleanup
    kill $pid 2>/dev/null || true
    ./build/torforge stop 2>/dev/null || true
    sleep 2
    
    echo ""
}

# Compare with kalitorify
benchmark_compare() {
    echo -e "${YELLOW}[5/5] Comparison with kalitorify...${NC}"
    
    if ! command -v kalitorify &> /dev/null; then
        echo -e "   ${YELLOW}kalitorify not installed, skipping comparison${NC}"
        return
    fi
    
    # TorForge startup
    local tf_start=$(date +%s.%N)
    timeout 120 ./build/torforge tor &
    local tf_pid=$!
    while ! curl -s --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip &>/dev/null; do
        sleep 1
    done
    local tf_end=$(date +%s.%N)
    local tf_time=$(echo "$tf_end - $tf_start" | bc)
    kill $tf_pid 2>/dev/null || true
    ./build/torforge stop 2>/dev/null || true
    sleep 2
    
    # Kalitorify startup
    local kf_start=$(date +%s.%N)
    kalitorify -t &
    while ! curl -s https://check.torproject.org/api/ip &>/dev/null; do
        sleep 1
    done
    local kf_end=$(date +%s.%N)
    local kf_time=$(echo "$kf_end - $kf_start" | bc)
    kalitorify -c 2>/dev/null || true
    sleep 2
    
    echo -e "   TorForge startup:   ${GREEN}${tf_time}s${NC}"
    echo -e "   Kalitorify startup: ${YELLOW}${kf_time}s${NC}"
    
    local speedup=$(echo "scale=2; $kf_time / $tf_time" | bc)
    echo -e "   Speedup: ${GREEN}${speedup}x faster${NC}"
    
    echo ""
}

# Run leak test
leak_test() {
    echo -e "${YELLOW}[BONUS] DNS Leak Test...${NC}"
    
    ./build/torforge tor &
    local pid=$!
    sleep 10
    
    # Try to resolve DNS directly (should fail)
    if timeout 3 dig @8.8.8.8 google.com +short &>/dev/null; then
        echo -e "   ${RED}WARNING: Direct DNS resolution succeeded (potential leak!)${NC}"
    else
        echo -e "   ${GREEN}PASS: Direct DNS blocked${NC}"
    fi
    
    # Check if using Tor
    local ip=$(curl -s --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip 2>/dev/null)
    if [ -n "$ip" ]; then
        echo -e "   ${GREEN}PASS: Tor connection working (exit IP: $ip)${NC}"
    else
        echo -e "   ${RED}FAIL: Could not connect through Tor${NC}"
    fi
    
    # Cleanup
    kill $pid 2>/dev/null || true
    ./build/torforge stop 2>/dev/null || true
    
    echo ""
}

# Main
check_deps

# Build if needed
if [ ! -f "./build/torforge" ]; then
    echo -e "${YELLOW}Building TorForge...${NC}"
    make build
fi

echo ""
benchmark_startup
benchmark_throughput
benchmark_latency
benchmark_memory
benchmark_compare
leak_test

echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                    Benchmark Complete!                       ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
