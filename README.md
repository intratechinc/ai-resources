# 🛡️ Intratech Cybersecurity Suite

## AI-Powered Multi-Agent Cybersecurity Platform

A comprehensive cybersecurity suite featuring 10 specialized AI agents for threat detection, vulnerability assessment, incident response, and security monitoring.

![Cybersecurity Suite](https://img.shields.io/badge/Security-AI--Powered-red)
![Python](https://img.shields.io/badge/Python-3.8+-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

## 🚀 Features

### 🤖 AI-Powered Agents
- **Coordinator Agent**: Task orchestration and routing
- **Threat Intelligence Agent**: IOC analysis and threat hunting
- **Vulnerability Scanner**: Security assessment and scanning
- **Penetration Testing Agent**: Ethical hacking and security testing
- **Incident Response Agent**: Automated incident management
- **OSINT Agent**: Open source intelligence gathering
- **Malware Analysis Agent**: Malware detection and analysis
- **Network Security Agent**: Network monitoring and protection
- **Compliance Agent**: Regulatory compliance checking
- **Forensics Agent**: Digital forensics and investigation

### 🌐 Web Interface
- Real-time dashboard with dark cybersecurity theme
- Interactive chat interface with AI agents
- Live agent status monitoring
- Task execution and management
- Security event tracking

### 🔧 Technical Features
- Flask web application with Socket.IO for real-time communication
- SQLite database with comprehensive security data models
- Multi-AI support (OpenAI GPT-4 + Anthropic Claude)
- Network intelligence integration (Shodan API)
- RESTful API endpoints
- WebSocket-based real-time updates

## 📋 Quick Start

### Prerequisites
- Python 3.8 or higher
- pip package manager
- Git

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/intratechinc/ai-resources.git
cd ai-resources
```

2. **Create virtual environment**
```bash
python -m venv venv

# Linux/Mac
source venv/bin/activate

# Windows
venv\Scripts\activate
```

3. **Install dependencies**
```bash
pip install -r requirements.txt
```

4. **Configure environment variables**
```bash
cp .env.example .env
# Edit .env file with your API keys (see Configuration section)
```

5. **Start the application**
```bash
python start.py
```

6. **Access the web interface**
Open your browser and go to: `http://localhost:5000`

## 🔑 Configuration

### Required API Keys

Create a `.env` file based on `.env.example` and configure the following:

#### OpenAI API Key (Required)
```env
OPENAI_API_KEY=your-openai-api-key-here
```
Get your key from [OpenAI Platform](https://platform.openai.com/api-keys)

#### Optional API Keys for Enhanced Features
```env
# Anthropic Claude AI (Optional)
ANTHROPIC_API_KEY=your-anthropic-api-key-here

# Shodan Network Intelligence (Optional)
SHODAN_API_KEY=your-shodan-api-key-here

# VirusTotal Malware Analysis (Optional)
VIRUSTOTAL_API_KEY=your-virustotal-api-key-here
```

### Environment Variables
```env
# Application Settings
SECRET_KEY=your-secret-key-here
DEBUG=True
DATABASE_URL=sqlite:///cybersecurity_suite.db

# Logging
LOG_LEVEL=INFO
LOG_FILE=logs/cybersecurity_suite.log

# Agent Configuration
AGENT_UPDATE_INTERVAL=60
MAX_CONCURRENT_TASKS=10
```

## 🖥️ Usage

### Web Interface
- **Dashboard**: Access at `http://localhost:5000`
- **Chat Interface**: Interactive AI agent communication
- **Agent Status**: Real-time monitoring of all agents
- **Task Management**: Execute and track security tasks
- **Event Monitoring**: View security events and alerts

### API Endpoints
```bash
# Health check
GET /health

# Agent information
GET /api/agents
GET /api/agents/{agent_type}

# Security events
GET /api/security-events

# System logs
GET /api/logs
```

### Chat Commands Examples
```
# Vulnerability Assessment
"Scan 192.168.1.1 for vulnerabilities"

# Threat Intelligence
"Check if example.com is malicious"

# OSINT Investigation
"Research information about example-company.com"

# Incident Response
"Analyze this security alert: suspicious login from IP 10.0.0.1"

# Malware Analysis
"Analyze this file hash: d41d8cd98f00b204e9800998ecf8427e"
```

## 🛠️ Development

### Project Structure
```
cybersecurity-suite/
├── agents/                 # AI agent implementations
│   ├── base_agent.py      # Base agent class
│   ├── coordinator.py     # Main coordinator
│   ├── threat_intelligence.py
│   ├── vulnerability_scanner.py
│   └── ...
├── templates/             # HTML templates
├── static/               # CSS, JS, images
├── logs/                 # Application logs
├── uploads/              # File uploads
├── app.py                # Main Flask application
├── start.py              # Application startup script
├── config.py             # Configuration management
├── database.py           # Database models
├── requirements.txt      # Python dependencies
└── .env.example          # Environment template
```

### Adding New Agents
1. Create a new agent class inheriting from `BaseAgent`
2. Implement required methods: `get_system_prompt()`, `process_message()`, `execute_task()`
3. Register the agent in `app.py`
4. Add routing logic in `coordinator.py`

### Database Schema
The application uses SQLite with these main tables:
- `agent_logs` - Agent activity logs
- `security_events` - Security incidents and events
- `threat_intelligence` - IOC and threat data
- `vulnerability_assessments` - Vulnerability scan results
- `network_assets` - Network inventory
- `compliance_checks` - Compliance audit results

## 🔒 Security Considerations

### API Key Security
- ⚠️ **Never commit API keys to version control**
- Use environment variables for all sensitive data
- Regularly rotate API keys
- Monitor API key usage for anomalies

### Network Security
- Run behind a reverse proxy in production
- Use HTTPS for all communications
- Implement rate limiting
- Monitor for suspicious activity

### Data Protection
- Encrypt sensitive data at rest
- Use secure database connections
- Implement proper access controls
- Regular security audits

## 🚀 Deployment

### Local Development
```bash
python start.py
```

### Production Deployment
1. Set up a proper web server (nginx, Apache)
2. Use a production WSGI server (gunicorn, uWSGI)
3. Configure SSL/TLS certificates
4. Set up monitoring and logging
5. Implement backup strategies

### Docker Deployment
```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
EXPOSE 5000
CMD ["python", "start.py"]
```

## 📊 Monitoring

### Health Checks
- Application health: `GET /health`
- Agent status: `GET /api/agents`
- Database connectivity checks
- API key validation

### Logging
- Application logs: `logs/cybersecurity_suite.log`
- Agent activity logs in database
- Security event tracking
- Performance metrics

## 🔄 Updates

### Latest Changes
- ✅ Fixed LangChain deprecation warnings
- ✅ Updated to modern LangChain architecture
- ✅ Enhanced security with proper .gitignore
- ✅ Improved error handling and logging
- ✅ Added comprehensive API documentation

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines
- Follow PEP 8 style guidelines
- Add tests for new features
- Update documentation
- Ensure security best practices

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

### Getting Help
- Create an issue in the repository
- Check the documentation
- Review the logs for error messages
- Join our community discussions

### Common Issues
- **API Key Errors**: Ensure all required API keys are configured in `.env`
- **Import Errors**: Run `pip install -r requirements.txt` to install dependencies
- **Port Conflicts**: Change the port in `start.py` if 5000 is in use

## ⚠️ Disclaimer

This tool is for educational and authorized security testing purposes only. Users are responsible for complying with all applicable laws and regulations. The developers are not responsible for any misuse of this software.

## 🔗 Links

- [OpenAI API Documentation](https://platform.openai.com/docs)
- [Anthropic Claude Documentation](https://docs.anthropic.com/)
- [Shodan API Documentation](https://developer.shodan.io/)
- [Flask Documentation](https://flask.palletsprojects.com/)

---

**Built with ❤️ by the Intratech Security Team**

*Securing the digital world, one AI agent at a time.* 🛡️
