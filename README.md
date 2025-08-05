# ShadowCommand C2 Framework
![Animation4](https://github.com/user-attachments/assets/e419daca-1456-4397-899e-1daf6907d9e7)

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey.svg)]()
[![Language](https://img.shields.io/badge/language-C%23-blue.svg)]()

A sophisticated Command and Control (C2) framework designed for educational and authorized penetration testing and red team operations. ShadowCommand provides enterprise-grade features with modern evasion techniques and innovative communication channels.

## ⚠️ LEGAL DISCLAIMER

**THIS TOOL IS FOR AUTHORIZED PENETRATION TESTING AND EDUCATIONAL PURPOSES ONLY**

- Only use on systems you own or have explicit written permission to test
- Users are solely responsible for compliance with all applicable laws and regulations
- Misuse of this tool may violate local, state, federal, or international laws
- The authors assume no liability and are not responsible for any misuse or damage

**By using this software, you agree to use it responsibly and legally.**

##  Features

### Core C2 Capabilities
- **Multi-platform support** - Windows and Linux clients with intelligent shell detection
- **TLS encryption** - Secure communications with automatic certificate generation
- **Real-time operations** - Live command execution with progress indicators
- **File operations** - Upload/download with progress tracking and integrity checks
- **Screenshot capture** - Desktop screenshots on Windows clients
- **Advanced persistence** - Multiple persistence mechanisms across platforms

### Advanced Features
- **Multiplayer operators** - Multiple simultaneous operators with role-based access
- **Discord integration** - Complete C2 operations through Discord channels
- **Telegram notifications** - Real-time beacon alerts and status updates
- **PowerShell integration** - Automatic module loading (PowerView, PowerUp, etc.)
- **Privilege escalation** - Built-in techniques for gaining SYSTEM privileges
- **Anti-analysis evasion** - Sandbox detection, anti-debug, and memory protection
- **Lateral movement** - SCShell pivoting for Windows environments

### Operator Experience
- **Rich GUI interface** - Intuitive Windows Forms application
- **Enhanced file explorer** - Browse target filesystems with context menus
- **Activity monitoring** - Real-time logging with color-coded messages
- **Session management** - Connect/disconnect from multiple beacons
- **Command history** - Full command and response logging

##  Requirements

### Server Requirements
- Windows 10/11 or Windows Server 2016+
- .NET Framework 4.8 or .NET 6.0+

### Target Requirements
- **Windows**: Windows 7+ 
- **Linux**: Linux distribution with networking capabilities

##  Installation

### Quick Start
Please refer to the wiki

##  Contributing

We welcome contributions from the security community:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-capability`)
3. Commit your changes (`git commit -am 'Add new capability'`)
4. Push to the branch (`git push origin feature/new-capability`)
5. Create a Pull Request

### Development Guidelines
- Follow existing code style and conventions
- Add comprehensive error handling
- Include appropriate security disclaimers
- Test thoroughly before submitting
- Document new features and APIs

##  Documentation

- [Installation Guide](docs/installation.md)
- [Configuration Reference](docs/configuration.md)
- [Command Reference](docs/commands.md)
- [API Documentation](docs/api.md)
- [Troubleshooting](docs/troubleshooting.md)


## 📝 Changelog

### v1.6.0 (Latest)
- Added Discord C2 integration
- Implemented multiplayer operator support
- Enhanced PowerShell module auto-loading
- Improved anti-analysis evasion
- Added Linux client support
- Enhanced file explorer interface

### v1.5.0
- Added Telegram notifications
- Implemented privilege escalation techniques
- Enhanced persistence mechanisms
- Improved TLS certificate management
