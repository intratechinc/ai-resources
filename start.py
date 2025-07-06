#!/usr/bin/env python3
"""
Startup script for Intratech Cybersecurity Suite
Checks dependencies and starts the application
"""

import os
import sys
import subprocess
import platform
from pathlib import Path

def check_python_version():
    """Check if Python version is compatible"""
    if sys.version_info < (3, 8):
        print("❌ Error: Python 3.8 or higher is required")
        print(f"Current version: {platform.python_version()}")
        sys.exit(1)
    else:
        print(f"✅ Python version {platform.python_version()} is compatible")

def check_dependencies():
    """Check if required packages are installed"""
    required_packages = [
        'flask', 'flask-socketio', 'requests', 'openai', 
        'langchain_openai', 'langchain_core', 'rich', 'colorama', 'pandas'
    ]
    
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package.replace('-', '_'))
            print(f"✅ {package} is installed")
        except ImportError:
            missing_packages.append(package)
            print(f"❌ {package} is missing")
    
    if missing_packages:
        print(f"\n📦 Installing missing packages: {', '.join(missing_packages)}")
        try:
            subprocess.check_call([
                sys.executable, '-m', 'pip', 'install'
            ] + missing_packages)
            print("✅ All packages installed successfully")
        except subprocess.CalledProcessError:
            print("❌ Failed to install packages. Please run: pip install -r requirements.txt")
            sys.exit(1)

def create_directories():
    """Create necessary directories"""
    directories = ['logs', 'uploads', 'templates']
    
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)
        print(f"✅ Directory '{directory}' is ready")

def check_environment():
    """Check environment configuration"""
    env_file = Path('.env')
    
    if not env_file.exists():
        print("⚠️  Warning: .env file not found")
        print("📋 Creating .env file from example...")
        
        example_file = Path('.env.example')
        if example_file.exists():
            import shutil
            shutil.copy('.env.example', '.env')
            print("✅ .env file created from example")
            print("🔑 Please edit .env file with your API keys")
        else:
            print("❌ .env.example file not found")
            return False
    
    # Load environment variables
    if env_file.exists():
        with open(env_file) as f:
            for line in f:
                if '=' in line and not line.startswith('#'):
                    key, value = line.strip().split('=', 1)
                    os.environ[key] = value
    
    # Check for required API keys
    openai_key = os.environ.get('OPENAI_API_KEY')
    if not openai_key or openai_key == 'your-openai-api-key-here':
        print("⚠️  Warning: OpenAI API key not configured")
        print("🔑 Please set OPENAI_API_KEY in your .env file")
        return False
    else:
        print("✅ OpenAI API key is configured")
    
    return True

def start_application():
    """Start the Intratech Cybersecurity Suite"""
    print("\n🛡️  Starting Intratech Cybersecurity Suite...")
    print("🌐 Web interface will be available at: http://localhost:5000")
    print("🔄 Initializing agents and starting server...\n")
    
    try:
        # Import and run the main application
        from app import app, socketio, logger
        
        print("🚀 All systems ready!")
        print("=" * 60)
        
        # Start the Flask-SocketIO server
        socketio.run(
            app, 
            host='0.0.0.0', 
            port=5000, 
            debug=os.environ.get('DEBUG', 'True').lower() == 'true',
            allow_unsafe_werkzeug=True  # For development only
        )
        
    except ImportError as e:
        print(f"❌ Failed to import application: {e}")
        print("🔧 Please check your installation and dependencies")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n\n👋 Shutting down Intratech Cybersecurity Suite...")
        print("🛡️  Stay secure!")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        sys.exit(1)

def main():
    """Main startup function"""
    print("🛡️  Intratech Cybersecurity Suite")
    print("=" * 40)
    print("🔍 Performing startup checks...\n")
    
    # Perform all checks
    check_python_version()
    check_dependencies()
    create_directories()
    
    if not check_environment():
        print("\n⚠️  Configuration issues detected.")
        print("📝 Please configure your .env file and try again.")
        sys.exit(1)
    
    print("\n✅ All startup checks passed!")
    print("🎯 Ready to launch the cybersecurity suite...")
    
    # Start the application
    start_application()

if __name__ == "__main__":
    main()