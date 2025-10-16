# 🛡️ Security Training Lab for OWASP Juice Shop

This repository contains a comprehensive security training platform for OWASP Juice Shop with AI-powered monitoring, attack simulation, and real-time threat detection.

## 📌 Project Overview

This project provides a complete environment for security training with:

- **AI-powered monitoring dashboard** for real-time attack detection
- **Automated attack simulations** (SQL injection, XSS, Path Traversal, Brute Force)
- **Real-time threat detection** using machine learning models
- **Comprehensive reporting** for all security activities
- **Baseline activity generator** to simulate normal user behavior
- **Windows 11 compatible** setup with detailed troubleshooting

## 🧩 Directory Structure

```
SecurityTrainingLab/
├── juice-shop-app/                 # OWASP Juice Shop application
│   └── (Juice Shop files)
├── python-scripts/                # Python automation scripts
│   ├── monitoring/                # Monitoring and dashboard code
│   │   ├── flask_monitor.py       # Main monitoring dashboard
│   │   ├── templates/             # Dashboard HTML templates
│   │   │   └── dashboard.html   # Main dashboard UI
│   │   └── health_check.py        # System health monitoring
│   ├── attacks/                   # Attack simulation scripts
│   │   ├── sql_injection.py       # SQL injection attack
│   │   ├── xss_attack.py          # XSS attack
│   │   ├── path_traversal.py      # Path traversal attack
│   │   └── brute_force.py         # Brute force attack
│   ├── defense/                   # Security controls
│   │   └── security_controls_test.py # Security controls testing
│   ├── ai_models/                 # AI threat detection models
│   │   ├── MasterThreatModelV2.py
│   │   ├── master_threat_model.py # Model training script
│   │   ├── real_time_detector.py  # Real-time threat detection
│   │   ├── anomaly_detector.py    # Anomaly detection model
│   │   └── threat_detector.py     # Threat detection model
│   ├── reports/                   # Generated reports
│   ├── logs/                      # Log files
│   │   ├── application/           # Application logs
│   │   ├── security/              # Security event logs
│   │   └── performance/           # Performance metrics
│   ├── data-captures/             # Data capture files
│   │   ├── logs/
│   │   ├── metrics/
│   │   └── network/
│   ├── templates/                 # HTML templates
│   ├── models/                    # Trained AI models (Pickle files)
│   │   ├── master_threat_model.pkl
│   │   ├── text_model.pkl
│   │   ├── vectorizer.pkl
│   │   ├── anomaly_model.pkl
│   │   └── scaler.pkl
│   ├── run_training.py            # Main training script
│   ├── train_model_once.py        # Train AI model (run once)
│   ├── use_trained_model.py       # Use pre-trained AI model
│   ├── verify_setup.py            # Verify environment setup
│   └── monitoring/                # Monitoring scripts
├── documentation/               # Project documentation
│   ├── setup/                     # Setup documentation
│   ├── attacks/                   # Attack documentation
│   └── defense/                   # Defense documentation
└── backup-configs/              # Configuration backups
```

## 📦 Prerequisites

### 1. Software Installation
```bash
# 1. Install Node.js (LTS Version)
# Download from: https://nodejs.org/
node --version
npm --version

# 2. Install Python 3.9+
# Download from: https://python.org/
# Check "Add Python to PATH" during installation
python --version
pip --version

# 3. Install Git
# Download from: https://git-scm.com/
git --version

# 4. Install Visual Studio Code (Recommended)
# Download from: https://code.visualstudio.com/
```

### 2. Windows 11 Specific Configuration
```powershell
# Enable long paths in Windows
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v LongPathsEnabled /t REG_DWORD /d 1 /f

# Install Windows Build Tools for Python packages
npm install --global windows-build-tools
```

### 3. Create Virtual Environment
```bash
# Create virtual environment
python -m venv security-env

# Activate virtual environment (Command Prompt)
security-env\Scripts\activate.bat

# Activate virtual environment (PowerShell)
security-env\Scripts\Activate.ps1

# Activate virtual environment (Git Bash)
source security-env/Scripts/activate

# Install dependencies
pip install -r python-scripts/requirements.txt
```

## 🚀 Installation Steps

### 1. Setup OWASP Juice Shop

#### Method A: Direct Git Clone (Recommended)
```bash
cd SecurityTrainingLab
cd juice-shop-app
git clone https://github.com/juice-shop/juice-shop.git .
npm install
```

#### Method B: Docker Installation (Alternative)
```bash
# Install Docker Desktop on Windows 11 first
docker pull bkimminich/juice-shop
docker run -d -p 3000:3000 -p 3001:3001 --name juice-shop bkimminich/juice-shop
```

#### Windows-Specific Juice Shop Configuration
Create `juice-shop-app/start-juice-shop.bat`:
```batch
@echo off
echo Starting OWASP Juice Shop on Windows 11...
cd /d %~dp0
echo Checking Node.js installation...
node --version
if %errorlevel% neq 0 (
    echo Error: Node.js not found. Please install Node.js first.
    pause
    exit /b 1
)
echo Installing dependencies...
call npm install
echo Starting Juice Shop...
call npm start
echo Juice Shop should be running at: http://localhost:3000
pause
```

### 2. Run the Training Session

#### Step 1: Train AI Model (Run Once)
```bash
cd SecurityTrainingLab\python-scripts
python train_model_once.py
```

#### Step 2: Start Juice Shop
```bash
cd SecurityTrainingLab\juice-shop-app
start-juice-shop.bat
```

#### Step 3: Start the Security Training Lab
```bash
cd SecurityTrainingLab\python-scripts
python run_training.py
```

## 🖥️ Accessing the Dashboard

After starting the training session, access the dashboard at:
```
http://localhost:5000
```

The dashboard provides:
- Real-time attack monitoring
- System health metrics
- AI threat detection
- Attack simulation controls
- Security alerts and reports

## 📊 Key Features

### 1. AI-Powered Monitoring
- Real-time threat detection with confidence scoring
- Behavioral analysis and anomaly detection
- Attack timeline visualization
- System health monitoring

### 2. Attack Simulation
- SQL Injection
- XSS Attacks
- Path Traversal
- Brute Force
- Security Controls Testing
- Baseline Activity Simulation

### 3. Reporting System
- Detailed attack reports with success rates
- System health reports
- AI threat analysis
- Model performance monitoring

### 4. Model Management
- Pre-trained AI models (no need to retrain)
- One-time model training script
- Real-time threat detection
- Model health monitoring

## 📂 Report Files Structure

The `reports/` directory contains:
- `sql_injection_report.json` - SQL injection attack results
- `xss_attack_report.json` - XSS attack results
- `path_traversal_report.json` - Path traversal attack results
- `brute_force_report.json` - Brute force attack results
- `baseline_activity_report.json` - Normal user behavior patterns
- `ai_threat_analysis_report.json` - AI threat analysis results
- `anomaly_detection_report.json` - Anomaly detection results
- `security_controls_report.json` - Security controls test results
- `health_report.json` - System health check results
- `model_demo_results.json` - AI model demo results
- `model_monitoring_report.json` - AI model performance monitoring

Each report contains:
```json
{
  "timestamp": "2023-10-15T10:30:00",
  "attack_type": "SQL Injection",
  "summary": {
    "total_payloads_tested": 5,
    "successful_login_bypasses": 3,
    "vulnerabilities_found": 2,
    "success_rate": 60.0
  },
  "detailed_results": [
    {
      "payload_id": 1,
      "payload": "' OR '1'='1'--",
      "status_code": 200,
      "success": true,
      "timestamp": "2023-10-15T10:30:05"
    }
  ],
  "recommendations": [
    "Use parameterized queries or prepared statements",
    "Implement proper input validation",
    "Apply principle of least privilege for database accounts"
  ]
}
```

## 📁 Log Files Structure

The `logs/` directory contains:
- `application/` - General application logs
  - `health_check.log` - System health check logs
  - `training_20231015_104627.log` - Training session logs
- `security/` - Security event logs
  - `sql_injection.log` - SQL injection attack logs
  - `xss_attack.log` - XSS attack logs
  - `path_traversal.log` - Path traversal attack logs
  - `brute_force.log` - Brute force attack logs
  - `security_controls_test.log` - Security controls test logs
- `performance/` - Performance metrics

## 🧪 Verification

Verify your setup with:
```bash
python verify_setup.py
```

This script checks:
- Python version
- Node.js version
- Juice Shop status
- Dashboard status
- AI model status

## 🛠️ Troubleshooting

### Common Windows 11 Issues

#### Port Conflicts:
```cmd
# Check what's using port 3000
netstat -ano | findstr :3000

# Check what's using port 5000  
netstat -ano | findstr :5000

# Kill process by PID
taskkill /PID <PID> /F
```

#### Node.js Issues:
```cmd
# Clear npm cache
npm cache clean --force

# Reinstall dependencies
rmdir /s node_modules
npm install
```

#### Python Virtual Environment Issues:
```cmd
# Recreate virtual environment
rmdir /s security-env
python -m venv security-env
security-env\Scripts\activate.bat
pip install -r python-scripts\requirements.txt
```

## 🌐 Expected Output

After successful execution:
1. **Juice Shop Application**: http://localhost:3000
   - Vulnerable web application for testing
   - Complete with challenges and scoreboard
2. **Monitoring Dashboard**: http://localhost:5000  
   - Real-time attack monitoring
   - System health metrics
   - Security alerts and reports
   - Interactive charts and timelines
3. **Generated Reports**: `reports/` directory
   - SQL injection analysis
   - Brute force attack results
   - Health check reports
   - AI threat detection results
4. **Log Files**: `logs/` directory
   - Application logs
   - Security event logs
   - Performance metrics
   - Error tracking

## 📚 Usage Examples

### Run a specific attack:
```bash
python attacks/sql_injection.py
```

### Analyze text for threats:
```bash
python use_trained_model.py
# Enter text to analyze: ' OR 1=1--
```

### Check model health:
```bash
python monitor_model.py
```

### View the dashboard:
```
http://localhost:5000
```

## 📌 Important Notes

1. **Train the model once** using `train_model_once.py` - no need to retrain
2. **Do not modify** the `models/` directory after training
3. **All reports** are automatically loaded when you start the dashboard
4. **The dashboard** refreshes every 3 seconds with new data
5. **All logs** are stored in the `logs/` directory for later analysis



---

**This security training platform is designed for educational purposes only. Do not use it against systems without explicit permission.**
