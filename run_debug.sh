#!/bin/bash
# Debug Mode Runner for RAVPN Application
#
# NOTE: This script is OPTIONAL. You can run the application directly with:
#   python3 app.py
#
# The application automatically detects DEBUG_MODE from your .env file.
# This script just provides helpful validation and status messages.

echo "========================================="
echo "  RAVPN Application - Debug Mode"
echo "========================================="
echo ""
echo "ℹ️  Note: You can also run 'python3 app.py' directly."
echo "   The app auto-detects DEBUG_MODE from .env"
echo ""

# Check if .env file exists
if [ ! -f ".env" ]; then
    echo "⚠️  No .env file found!"
    echo "📝 Copying .env.debug to .env..."
    cp .env.debug .env
    echo "✅ Done! Please edit .env with your FMC credentials."
    echo ""
    read -p "Press Enter to continue after editing .env, or Ctrl+C to exit..."
fi

# Check if DEBUG_MODE is enabled
if ! grep -q "^DEBUG_MODE=True" .env; then
    echo "⚠️  DEBUG_MODE is not set to True in .env"
    echo "📝 Please set DEBUG_MODE=True in your .env file"
    exit 1
fi

echo "🔧 Debug Mode Configuration:"
echo "  ✓ Authentication: DISABLED"
echo "  ✓ HTTPS: DISABLED (HTTP only)"
echo "  ✓ CSRF SSL Strict: DISABLED"
echo "  ✓ WebSocket: Enabled over HTTP"
echo "  ✓ Binding: 0.0.0.0:5001"
echo ""
echo "🌐 Access the application at:"
echo "   http://localhost:5001"
echo "   http://$(hostname -I | awk '{print $1}'):5001"
echo ""
echo "⚠️  WARNING: This mode is for development only!"
echo "   Never use DEBUG_MODE=True in production!"
echo ""
echo "Starting server..."
echo "========================================="
echo ""

# Run the application
python3 app.py
