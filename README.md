# AI-Powered Integrated Web Security Scanner

A comprehensive multi-vector threat detection platform that combines file malware scanning, email security analysis, URL/IP reputation checking with machine learning.

## Features

### For All Users (Guest & Registered)
- 📁 **File Scanner**: Upload files for malware detection using ML models
- ✉️ **Email Analyzer**: Check DKIM/SPF/DMARC and detect phishing
- 🔗 **URL Scanner**: Verify website safety and reputation
- 🌐 **IP Checker**: Check IP address reputation and abuse history

### Additional Features for Registered Users
- 📊 **Dashboard**: View statistics and scan history
- 📝 **Scan History**: Access all previous scan results
- 📄 **Reports**: Download PDF/HTML reports
- 📧 **Email Notifications**: Receive scan results via email
- 🔄 **Batch Processing**: Upload multiple files at once (up to 10)

## Project Structure

```
security_scanner/
├── app/
│   ├── __init__.py           # Flask app factory
│   ├── models/               # Database models
│   │   ├── user.py          # User authentication model
│   │   └── scans.py         # Scan results models
│   ├── routes/               # Route handlers
│   │   ├── main.py          # Homepage, about
│   │   ├── auth.py          # Login, register, logout
│   │   └── scanner.py       # Scanning functionality
│   ├── static/               # CSS, JS, images
│   │   ├── css/
│   │   ├── js/
│   │   └── images/
│   ├── templates/            # HTML templates
│   └── utils/                # Helper functions
├── data/                     # SQLite database
├── ml_models/                # Trained ML models
├── uploads/                  # Temporary file uploads
├── reports/                  # Generated reports
├── config.py                 # Configuration settings
├── requirements.txt          # Python dependencies
├── .env                      # Environment variables
└── run.py                    # Application entry point
```

## Installation

### Windows Users (Easy Way) - Just 2 Steps! 🚀

#### Step 1: First Time Setup
```
Double-click: setup.bat
```
Wait ~5 minutes for installation to complete.

#### Step 2: Start Application
```
Double-click: start.bat
```
Open browser: http://localhost:5000

**That's it!** 🎉

See [BATCH_FILES_GUIDE.md](BATCH_FILES_GUIDE.md) for more details.

---

### Linux/Mac Users (Manual Installation)

#### 1. Create virtual environment
```bash
python3 -m venv venv
source venv/bin/activate
```

#### 2. Install dependencies
```bash
pip install -r requirements.txt
```

#### 3. Initialize database
```bash
python -c "from app import create_app, db; app = create_app(); app.app_context().push(); db.create_all()"
```

#### 4. Run the application
```bash
python run.py
```

Visit: http://localhost:5000

---

### Optional: Configure API Keys

Edit `.env` file and add your API keys:
- Google Safe Browsing API key
- AbuseIPDB API key

(The app works without these, but some features will be limited)

## Usage

### Guest Users
1. Visit the homepage
2. Click "Quick Scan" 
3. Choose scan type (File/Email/URL/IP)
4. View results immediately
5. Results are not saved

### Registered Users
1. Register an account
2. Log in
3. Access full dashboard
4. Perform scans (results saved automatically)
5. View scan history
6. Download reports

## Technology Stack

- **Backend**: Python 3.x, Flask
- **Database**: SQLite
- **ML**: Scikit-learn, Pandas, NumPy
- **Email Analysis**: dkimpy, dnspython, pyspf
- **External APIs**: Google Safe Browsing, AbuseIPDB
- **Frontend**: HTML, CSS, JavaScript, Bootstrap

## Development Status

### ✅ Completed
- Project structure
- Database models
- User authentication system
- Route structure
- Configuration setup

### 🚧 In Progress
- ML model training
- Frontend templates
- Scanning logic implementation

### 📋 To Do
- Email notification system
- Report generation
- Dashboard visualizations
- API integrations

## Security Notes

- Files are processed locally (not sent externally)
- Passwords are hashed using Werkzeug
- Session management with secure cookies
- Rate limiting to prevent abuse

## Contributing

This is a research project. Contributions and suggestions are welcome!

## License

Educational/Research Project

## Contact

For questions or support, please contact the project maintainer.
