# 🔍 OSINT/Recon Toolkit

A comprehensive, web-based Open Source Intelligence (OSINT) and reconnaissance toolkit designed for ethical security testing, research, and educational purposes.

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Screenshots](#screenshots)
- [Legal Disclaimer](#legal-disclaimer)
- [Contributing](#contributing)
- [License](#license)

## 🎯 Overview

The OSINT/Recon Toolkit is a professional-grade web application that automates common reconnaissance workflows including subdomain enumeration, port scanning, and data leak detection. Built with modern web technologies, it provides an intuitive interface for security professionals, researchers, and students.

## ✨ Features

### 🌐 Subdomain Enumeration
- Automated discovery of subdomains for target domains
- IP address resolution and status checking
- Real-time results with visual indicators
- Export capabilities for further analysis

### 🔌 Port Scanning
- Comprehensive port scanning with service identification
- Configurable port ranges (single ports, ranges, or custom lists)
- Banner grabbing and service detection
- Open port visualization with detailed information

### 💧 Data Leak Detection
- Breach database checking for domains and email addresses
- Historical leak analysis with severity ratings
- Data type identification (passwords, emails, usernames)
- Timeline tracking of discovered breaches

### 📊 Advanced Reporting
- Real-time statistics dashboard
- Multiple export formats (JSON, CSV, HTML)
- Professional report generation
- Comprehensive scan summaries

### 🎨 Modern UI/UX
- Responsive design that works on all devices
- Dark theme with gradient backgrounds
- Smooth animations and loading states
- Intuitive tab-based navigation
- Professional styling with modern CSS

## 🚀 Installation

1. **Clone or Download**
   ```bash
   git clone https://github.com/yourusername/osint-toolkit.git
   cd osint-toolkit
   ```

2. **Open in VS Code**
   ```bash
   code .
   ```

3. **Launch the Application**
   - Open the `index.html` file in your web browser
   - Or use VS Code Live Server extension for better development experience

## 📖 Usage

### Basic Workflow

1. **Select Your Tool**
   - Choose from Subdomain Enumeration, Port Scanning, or Leak Detection tabs

2. **Configure Target**
   - Enter your target domain, IP address, or email
   - Set appropriate parameters (port ranges, scan types, etc.)

3. **Execute Scan**
   - Click the scan button to begin reconnaissance
   - Monitor progress through the real-time loading indicators

4. **Analyze Results**
   - Review discovered information in the results panel
   - Use the statistics dashboard to get overview metrics

5. **Export Data**
   - Navigate to the Reports tab
   - Choose your preferred export format (JSON, CSV, or HTML)

### Subdomain Enumeration Usage
```
1. Navigate to "Subdomain Enumeration" tab
2. Enter target domain (e.g., example.com)
3. Click "🚀 Start Enumeration"
4. View discovered subdomains with IP addresses and status
5. Export results for further analysis
```

### Port Scanning Usage
```
1. Navigate to "Port Scanning" tab
2. Enter target host (IP or domain)
3. Specify port range (e.g., 1-1000 or 80,443,8080)
4. Click "🔍 Start Scan"
5. Review open ports with service information
```

### Leak Detection Usage
```
1. Navigate to "Leak Detection" tab
2. Enter domain or email address
3. Click "🔍 Check for Leaks"
4. Review potential data breaches and exposure
```


## ⚖️ Legal Disclaimer

**IMPORTANT: This tool is designed for authorized security testing, research, and educational purposes only.**

- Only use this toolkit on systems you own or have explicit written permission to test
- Unauthorized scanning may violate local, state, and federal laws
- Users are solely responsible for ensuring their use complies with applicable laws
- This tool is provided "as is" without warranty of any kind
- The authors are not responsible for any misuse or damage caused by this tool

## 🔒 Ethical Guidelines

- Always obtain proper authorization before scanning any systems
- Respect rate limits and avoid overwhelming target systems
- Use findings responsibly and report vulnerabilities through proper channels
- Follow responsible disclosure practices
- Respect privacy and confidentiality of discovered information

## 🛠️ Technical Stack

- **Frontend**: HTML5, CSS3, JavaScript (ES6+)
- **Styling**: Modern CSS with Flexbox/Grid, Custom animations
- **Architecture**: Single Page Application (SPA)
- **Export**: Client-side file generation (JSON, CSV, HTML)

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for:
- Bug fixes
- Feature enhancements
- Documentation improvements
- Security improvements

### Development Setup

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Inspired by industry-standard OSINT and reconnaissance tools
- Built with modern web development best practices
- Designed for educational and ethical security research

## 📞 Support

If you have any questions or need support:
- Open an issue on GitHub
- Check the documentation
- Follow ethical usage guidelines

---


**⚠️ Remember: With great power comes great responsibility. Use this tool ethically and legally.**
