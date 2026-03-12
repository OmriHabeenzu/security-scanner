# 🚀 Quick Start Guide - Batch Files

## Windows Batch Files for Easy Setup & Running

### 📁 Available Batch Files:

1. **setup.bat** - First-time setup (Run this FIRST!)
2. **start.bat** - Start the application
3. **stop.bat** - Stop the application
4. **install.bat** - Install/update dependencies only
5. **clean.bat** - Reset database (deletes all data)

---

## 🎯 Quick Start (3 Steps)

### Step 1: First Time Setup
```
Double-click: setup.bat
```
This will:
- Check Python installation
- Create virtual environment
- Install all dependencies
- Initialize database

**Time:** ~5 minutes

---

### Step 2: Start the Application
```
Double-click: start.bat
```
This will:
- Activate virtual environment
- Start the Flask server
- Open at http://localhost:5000

**Your browser:** http://localhost:5000

---

### Step 3: Stop the Application
```
Double-click: stop.bat
```
Or simply close the terminal window.

---

## 📋 Detailed Instructions

### 🔧 setup.bat - First Time Setup
**When to use:** 
- First time running the project
- After downloading/cloning the project

**What it does:**
1. Checks if Python is installed
2. Creates virtual environment (venv folder)
3. Installs all required packages from requirements.txt
4. Creates SQLite database with all tables

**Requirements:**
- Python 3.8 or higher installed
- Internet connection (to download packages)

**Output:**
- Creates `venv` folder
- Creates `data/security_scanner.db` file
- Installs ~25 Python packages

---

### ▶️ start.bat - Start Application
**When to use:**
- Every time you want to run the application
- After running setup.bat

**What it does:**
1. Activates virtual environment
2. Checks if database exists (creates if missing)
3. Starts Flask development server
4. Shows access URL

**Access the app:**
- Open browser: http://localhost:5000
- Or: http://127.0.0.1:5000

**Keep the terminal open** while using the app!

---

### ⏹️ stop.bat - Stop Application
**When to use:**
- When you want to stop the server
- Before shutting down computer
- To restart the application

**What it does:**
- Safely terminates Python/Flask processes

**Alternative:** 
Press `Ctrl+C` in the terminal window

---

### 📦 install.bat - Install/Update Dependencies
**When to use:**
- After updating requirements.txt
- To reinstall packages
- If packages get corrupted

**What it does:**
- Creates/activates virtual environment
- Installs/updates all packages
- Does NOT touch database

---

### 🗑️ clean.bat - Clean Database
**When to use:**
- Starting fresh with new database
- Testing purposes
- Clearing all data

**⚠️ WARNING:** This deletes:
- All user accounts
- All scan history
- All uploaded files
- All generated reports

**What it does:**
1. Asks for confirmation (type "yes")
2. Deletes database file
3. Deletes uploaded files
4. Deletes reports
5. Creates fresh empty database

---

## 🔍 Troubleshooting

### Error: "Python is not installed"
**Solution:**
1. Install Python from https://python.org
2. During installation, check "Add Python to PATH"
3. Restart computer
4. Run setup.bat again

---

### Error: "Virtual environment not found"
**Solution:**
Run `setup.bat` first to create the environment

---

### Error: Port 5000 already in use
**Solution:**
1. Run `stop.bat`
2. Or change port in run.py (line with `app.run`)
3. Or kill process: `taskkill /F /IM python.exe`

---

### Database errors
**Solution:**
1. Run `clean.bat` to reset database
2. Run `start.bat` again

---

## 📝 Typical Workflow

### First Day:
```
1. Double-click: setup.bat (wait ~5 minutes)
2. Double-click: start.bat
3. Open browser: http://localhost:5000
4. Create account and test features
5. Close terminal when done (or run stop.bat)
```

### Every Other Day:
```
1. Double-click: start.bat
2. Open browser: http://localhost:5000
3. Use the application
4. Close terminal when done
```

### If Something Breaks:
```
1. Run: clean.bat (to reset database)
2. Run: install.bat (to fix packages)
3. Run: start.bat (to test)
```

---

## 🎓 Advanced Tips

### Running in Background
To run without terminal window:
```
pythonw run.py
```

### Custom Port
Edit `run.py`, change:
```python
app.run(host='0.0.0.0', port=5000)
```
to:
```python
app.run(host='0.0.0.0', port=8080)  # or any port
```

### Production Mode
Edit `.env` file:
```
FLASK_ENV=production
```

---

## 📞 Need Help?

### Check These First:
1. Is Python installed? `python --version`
2. Did you run setup.bat first?
3. Is port 5000 available?
4. Any error messages in terminal?

### Common Solutions:
- Restart computer
- Run as Administrator
- Check antivirus isn't blocking
- Re-run setup.bat

---

## ✅ Quick Checklist

Before first run:
- [ ] Python 3.8+ installed
- [ ] Extracted project files
- [ ] Ran setup.bat successfully
- [ ] No errors in terminal

To use daily:
- [ ] Just double-click start.bat
- [ ] Open http://localhost:5000
- [ ] Done!

---

**That's it! You're ready to use SecureCheck!** 🎉
