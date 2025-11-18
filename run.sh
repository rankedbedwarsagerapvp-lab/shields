#!/bin/bash

# Shield Protection System - Run Script
# Автоматический запуск Shield с веб-панелью

echo "╔═══════════════════════════════════════════════╗"
echo "║   Shield Protection System v1.0               ║"
echo "║   Starting with Web Panel...                  ║"
echo "╚═══════════════════════════════════════════════╝"
echo ""

# Check if shield binary exists
if [ ! -f "./build/shield" ]; then
    echo "❌ Error: Shield binary not found!"
    echo "Please build first: go build -o build/shield cmd/shield/main.go"
    exit 1
fi

# Check if config.yaml exists
if [ ! -f "./config.yaml" ]; then
    echo "⚠️  Warning: config.yaml not found, using defaults"
fi

# Check if panel.html exists
if [ ! -f "./panel.html" ]; then
    echo "⚠️  Warning: panel.html not found, web panel may not work"
fi

echo "✅ Shield binary found"
echo "✅ Configuration ready"
echo ""
echo "🚀 Starting Shield..."
echo "   Minecraft: 0.0.0.0:25565"
echo "   Web Panel: http://localhost:8080"
echo ""
echo "📊 Open web panel: open http://localhost:8080"
echo "⏹️  Stop Shield: Ctrl+C"
echo ""
echo "────────────────────────────────────────────────"
echo ""

# Run Shield
./build/shield

# If Shield exits
echo ""
echo "Shield stopped."

