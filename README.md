# Password Quality Checker Documentation

## Table of Contents

1. [Introduction](#introduction)
2. [Project Overview](#project-overview)
3. [Features](#features)
4. [Technical Specifications](#technical-specifications)
5. [Architecture and Design](#architecture-and-design)
6. [Detailed Code Explanation](#detailed-code-explanation)
   - [Project Structure](#project-structure)
   - [Imports and Dependencies](#imports-and-dependencies)
   - [Constants](#constants)
   - [1. GUI Module (`gui.py`)](#1-gui-module-guipy)
   - [2. Front-End Logic Module (`frontend.py`)](#2-front-end-logic-module-frontendpy)
   - [3. Back-End Logic Module (`backend.py`)](#3-back-end-logic-module-backendpy)
   - [4. Database Module (`database.py`)](#4-database-module-databasepy)
   - [5. Main Script (`main.py`)](#5-main-script-mainpy)
7. [Installation and Setup](#installation-and-setup)
8. [Usage Guide](#usage-guide)
9. [Testing and Validation](#testing-and-validation)
10. [Future Enhancements](#future-enhancements)
11. [Conclusion](#conclusion)
12. [Appendix](#appendix)
    - [Dependencies](#dependencies)
    - [License](#license)

---

## Introduction

Group project where we have developed the **Password Quality Checker** application for St. Cloud State University's class **SE 480 Software Project Management**.

## Project Overview

The **Password Quality Checker** is a desktop application built using Python's PyQt6 framework. It offers users a comprehensive suite of tools to evaluate password strength, ensure compliance with industry standards, and manage password histories securely. Key functionalities include:

- **Password Strength Evaluation:** Assess passwords based on length, complexity, and entropy.
- **Compromised Password Detection:** Utilize the Have I Been Pwned (HIBP) API to check if passwords have been exposed in data breaches.
- **Password Generation:** Suggest strong, unique passwords adhering to customizable policies.
- **Password History Management:** Securely store and manage previously used passwords.
- **Customization Options:** Allow users to define password policies and settings.
- **Educational Resources:** Provide guidelines and best practices for password creation and management.
- **User Support:** Offer FAQs and help resources for troubleshooting and guidance.

## Features

1. **Password Strength Meter:** Visually represents the strength of a password as users type, categorized into Weak, Moderate, and Strong levels.

2. **Compromised Password Check:** Integrates with the HIBP API to verify if a password has been compromised in known data breaches, ensuring users avoid vulnerable credentials.

3. **Password Generation:** Generates secure, random passwords that meet user-defined criteria, enhancing security and convenience.

4. **Password History:** Maintains an encrypted history of generated passwords, allowing users to review and export past credentials.

5. **Customization Options:**
   - **Password Length:** Set minimum and maximum character limits.
   - **Character Requirements:** Enforce inclusion of uppercase, lowercase, digits, and special characters.
   - **Password Expiration:** Define policies for regular password updates.
   - **History Size:** Configure the maximum number of password entries stored.

6. **Educational Tabs:**
   - **Resources:** Access to NIST guidelines, OWASP policies, password manager information, and more.
   - **FAQ:** Comprehensive answers to common password-related queries.
   - **Help:** Instructions and tips for effective application usage.

7. **Security Measures:**
   - **Encryption:** Utilizes Fernet symmetric encryption to secure stored passwords.
   - **Rate Limiting Handling:** Manages API rate limits gracefully to ensure continuous functionality.
   - **Data Privacy:** Ensures that passwords are neither stored nor transmitted in plaintext.

## Technical Specifications

- **Programming Language:** Python 3.8+
- **Framework:** PyQt6
- **Database:** SQLite3
- **Encryption:** Cryptography's Fernet (symmetric encryption)
- **API Integration:** Have I Been Pwned (HIBP) Passwords API
- **Operating Systems:** Windows, macOS, Linux

## Architecture and Design

The application follows a modular architecture, segregating functionalities into distinct components to enhance maintainability and scalability. The project is organized into five separate Python scripts, all located within the `PQC` folder:

1. **GUI Module (`gui.py`):** Manages the graphical user interface using PyQt6, providing a responsive and intuitive user experience.

2. **Front-End Logic Module (`frontend.py`):** Acts as an intermediary between the GUI and the backend logic, handling user interactions, settings management, and data flow.

3. **Back-End Logic Module (`backend.py`):** Contains the core functionalities, including password evaluation, strength calculation, compromised password checks, and content for resources, FAQs, and help sections.

4. **Database Module (`database.py`):** Manages the SQLite database for storing encrypted password histories and handles encryption and decryption processes.

5. **Main Script (`main.py`):** Initializes the application, creates instances of the GUI and front-end logic, and starts the event loop.

### Modular Breakdown

- **Separation of Concerns:** Each module has a distinct responsibility, improving code readability and facilitating easier maintenance and testing.

- **Inter-module Communication:** The modules interact through well-defined interfaces and shared data structures, ensuring a cohesive application workflow.

- **Reusability:** Components like the backend logic and database modules can be reused or extended independently, promoting modular development practices.

The modular design emphasizes security, efficiency, and user-centric development, ensuring that users can manage their passwords confidently and effortlessly.

## Detailed Code Explanation

The **Password Quality Checker** application is meticulously crafted to ensure robust password evaluation, secure storage, and user-friendly interactions. This section delves into the intricacies of the application's codebase, elucidating the purpose and functionality of each component.

### Project Structure

All the Python scripts are located within the `PQC` folder:

```
PQC/
├── gui.py
├── frontend.py
├── backend.py
├── database.py
└── main.py
```

### Imports and Dependencies

```python
# Common imports across modules
import sys
import re
import random
import string
import datetime
import sqlite3
import math
import hashlib
import requests  # For making HTTP requests
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QLabel, QLineEdit, QPushButton,
    QVBoxLayout, QTextEdit, QComboBox, QListWidget, QTabWidget, QCheckBox,
    QSpinBox, QProgressBar, QFileDialog, QMessageBox, QHBoxLayout, QTextBrowser
)
from PyQt6.QtCore import Qt, QSettings, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QPalette, QColor
from cryptography.fernet import Fernet  # For encryption
```

- **Standard Libraries:**
  - `sys`: Handles system-specific parameters and functions.
  - `re`: Utilizes regular expressions for pattern matching.
  - `random`, `string`: Facilitates password generation with randomness and character sets.
  - `datetime`: Manages date and time-related operations.
  - `sqlite3`: Interfaces with the SQLite database for password history management.
  - `math`, `hashlib`: Provides mathematical functions and hashing capabilities.

- **Third-Party Libraries:**
  - `requests`: Manages HTTP requests, particularly for interacting with the HIBP API.
  - `PyQt6`: Constructs the graphical user interface (GUI) components.
  - `cryptography.fernet`: Implements symmetric encryption to secure stored passwords.

### Constants

```python
# Constants
DEFAULT_MAX_HISTORY_SIZE = 100  # Default maximum number of password history entries
DEFAULT_PASSWORD_EXPIRATION_DAYS = 90  # Default password expiration period
ENCRYPTION_KEY_FILE = 'encryption.key'  # File to store the encryption key
HIBP_API_URL = "https://api.pwnedpasswords.com/range/"  # Base URL for HIBP API
```

- **DEFAULT_MAX_HISTORY_SIZE:** Sets the initial limit for the number of password entries stored in history.
- **DEFAULT_PASSWORD_EXPIRATION_DAYS:** Defines the default period after which passwords should be updated.
- **ENCRYPTION_KEY_FILE:** Specifies the filename where the encryption key is stored.
- **HIBP_API_URL:** Base endpoint for querying the Have I Been Pwned (HIBP) API using the k-Anonymity model.

### 1. GUI Module (`gui.py`)

```python
# gui.py

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QLabel, QLineEdit, QPushButton,
    QVBoxLayout, QTextEdit, QComboBox, QListWidget, QTabWidget, QCheckBox,
    QSpinBox, QProgressBar, QFileDialog, QTextBrowser
)
from PyQt6.QtGui import QPalette, QColor

class PasswordQualityCheckerGUI(QMainWindow):
    def __init__(self, frontend_logic):
        super().__init__()
        self.frontend_logic = frontend_logic
        self.settings = self.frontend_logic.settings
        self.setWindowTitle("Password Quality Checker")
        self.setGeometry(100, 100, 600, 800)
        self.initUI()

    def initUI(self):
        # Palette and stylesheet configuration
        palette = QPalette()
        palette.setColor(QPalette.ColorRole.Window, QColor("#000000"))  # Black background
        palette.setColor(QPalette.ColorRole.WindowText, QColor("#FFFFFF"))  # White text
        self.setPalette(palette)

        # Apply stylesheets for widgets
        self.setStyleSheet("""
            QWidget {
                background-color: #000000;  /* Black background */
                color: #FFFFFF;  /* White text */
            }
            QPushButton {
                background-color: #8B0000;  /* Dark red */
                color: #FFFFFF;  /* White text */
                border: none;
                padding: 10px;
                border-radius: 5px;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #B22222;  /* Lighter red on hover */
            }
            QLineEdit, QTextEdit, QSpinBox, QComboBox, QListWidget {
                background-color: #1C1C1C;  /* Dark grey background */
                color: #FFFFFF;  /* White text */
                border: 1px solid #8B0000;
                padding: 5px;
                font-size: 14px;
            }
            QProgressBar {
                text-align: center;
                border: 1px solid #8B0000;
                border-radius: 5px;
                background-color: #1C1C1C;
            }
            QProgressBar::chunk {
                background-color: #B22222;
                width: 1px;
            }
            QTabWidget::pane { /* The tab widget frame */
                border-top: 2px solid #8B0000;
            }
            QTabBar::tab {
                background: #1C1C1C;
                color: #FFFFFF;
                padding: 10px;
                font-size: 14px;
            }
            QTabBar::tab:selected {
                background: #8B0000;
            }
            QCheckBox, QLabel {
                color: #FFFFFF;
                font-size: 14px;
            }
        """)

        # Main layout and tabs initialization
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QVBoxLayout()

        # Tab widget
        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)

        # Initialize all the tabs
        self.initTabs()

        main_widget.setLayout(main_layout)

    def initTabs(self):
        # Password Checker Tab
        self.checker_tab = QWidget()
        self.tabs.addTab(self.checker_tab, "Password Checker")
        self.frontend_logic.initCheckerTab(self.checker_tab)

        # Resources Tab
        self.resources_tab = QWidget()
        self.tabs.addTab(self.resources_tab, "Resources")
        self.frontend_logic.initResourcesTab(self.resources_tab)

        # FAQ Tab
        self.faq_tab = QWidget()
        self.tabs.addTab(self.faq_tab, "FAQ")
        self.frontend_logic.initFAQTab(self.faq_tab)

        # Password History Tab
        self.history_tab = QWidget()
        self.tabs.addTab(self.history_tab, "Password History")
        self.frontend_logic.initHistoryTab(self.history_tab)

        # Options Tab
        self.options_tab = QWidget()
        self.tabs.addTab(self.options_tab, "Options")
        self.frontend_logic.initOptionsTab(self.options_tab)

        # Help Tab
        self.help_tab = QWidget()
        self.tabs.addTab(self.help_tab, "Help")
        self.frontend_logic.initHelpTab(self.help_tab)

    def closeEvent(self, event):
        self.frontend_logic.database.close()
        event.accept()
```

- **Purpose:** Manages all the visual components and layouts of the application using PyQt6.

- **Components:**
  - **Tabs:** Organizes the UI into tabs such as Password Checker, Resources, FAQ, Password History, Options, and Help.
  - **Widgets:** Includes labels, input fields, buttons, checkboxes, progress bars, and text areas for user interaction.

- **Interactions:** Connects GUI events (like button clicks) to methods in the front-end logic module, ensuring user actions trigger the appropriate responses.

### 2. Front-End Logic Module (`frontend.py`)

```python
# frontend.py

from PyQt6.QtWidgets import QApplication, QLineEdit, QFileDialog
from PyQt6.QtCore import QSettings
from backend import PasswordEvaluator, PasswordCheckThread
from database import PasswordDatabase

class PasswordQualityCheckerFrontend:
    def __init__(self, gui):
        self.gui = gui
        self.settings = QSettings("AshleyMGreerProjects", "SE-480---Password-Quality-Checker")
        # Load settings and initialize components
        self.loadSettings()

        # Initialize backend components
        self.password_evaluator = PasswordEvaluator(self)
        self.database = PasswordDatabase(self)
        self.generated_password = None

        # Initialize database and load history
        self.database.initDB()
        self.database.initEncryption()

    def loadSettings(self):
        self.minimum_length = self.settings.value("minimum_length", 8, type=int)
        self.maximum_length = self.settings.value("maximum_length", 128, type=int)
        self.compromised_check_enabled = self.settings.value("compromised_check_enabled", True, type=bool)
        self.require_uppercase = self.settings.value("require_uppercase", True, type=bool)
        self.require_lowercase = self.settings.value("require_lowercase", True, type=bool)
        self.require_digits = self.settings.value("require_digits", True, type=bool)
        self.require_special = self.settings.value("require_special", True, type=bool)
        self.max_history_size = self.settings.value("max_history_size", DEFAULT_MAX_HISTORY_SIZE, type=int)
        self.password_expiration_days = self.settings.value("password_expiration_days", DEFAULT_PASSWORD_EXPIRATION_DAYS, type=int)

    # Define methods to handle user interactions and update settings
    def initCheckerTab(self, tab):
        # Initialize the Password Checker Tab
        # (Implementation similar to the original script)
        pass

    def initResourcesTab(self, tab):
        # Initialize the Resources Tab
        # (Implementation similar to the original script)
        pass

    def initFAQTab(self, tab):
        # Initialize the FAQ Tab
        # (Implementation similar to the original script)
        pass

    def initHistoryTab(self, tab):
        # Initialize the Password History Tab
        # (Implementation similar to the original script)
        pass

    def initOptionsTab(self, tab):
        # Initialize the Options Tab
        # (Implementation similar to the original script)
        pass

    def initHelpTab(self, tab):
        # Initialize the Help Tab
        # (Implementation similar to the original script)
        pass

    # Additional methods to handle events, update settings, and interact with the backend and database
    # ...
```

- **Purpose:** Acts as a bridge between the GUI and the backend logic, handling user interactions, settings updates, and data flow.

- **Responsibilities:**
  - **Settings Management:** Loads and updates user preferences using `QSettings`.
  - **User Interaction Handling:** Responds to GUI events by invoking appropriate backend methods.
  - **Data Management:** Coordinates data retrieval and storage with the database module.

- **Components:**
  - **Password Evaluator Instance:** Utilizes the backend logic for password evaluations.
  - **Database Instance:** Manages password history storage and retrieval.

### 3. Back-End Logic Module (`backend.py`)

```python
# backend.py

import math
import re
import string
import random
import hashlib
import requests
from PyQt6.QtCore import QThread, pyqtSignal

class PasswordEvaluator:
    def __init__(self, frontend):
        self.frontend = frontend

    def calculateEntropy(self, password):
        pool = 0
        if re.search(r'[a-z]', password):
            pool += 26
        if re.search(r'[A-Z]', password):
            pool += 26
        if re.search(r'\d', password):
            pool += 10
        if re.search(r'[^\w\s]', password):
            pool += 32  # Approximate number of special characters
        entropy = len(password) * math.log2(pool) if pool > 0 else 0
        return entropy

    def evaluatePassword(self, password):
        """
        Evaluate the password's strength and check if it meets policy requirements.
        Returns a tuple of (strength, feedback).
        """
        length = len(password)
        # Evaluation logic including policy checks and entropy calculation
        # Returns (strength, feedback)
        # (Implementation similar to the original script)
        pass

    def generateStrongPassword(self):
        """
        Generate a strong random password that meets the minimum length and is not compromised.
        """
        # Password generation logic
        # (Implementation similar to the original script)
        pass

    def getResourceContent(self, index):
        # Returns HTML content for selected resource
        # (Implementation similar to the original script)
        pass

    def getFAQContent(self):
        # Returns HTML content for FAQ section
        # (Implementation similar to the original script)
        pass

    def getHelpContent(self):
        # Returns HTML content for Help section
        # (Implementation similar to the original script)
        pass

class PasswordCheckThread(QThread):
    result = pyqtSignal(bool, int)

    def __init__(self, password):
        super().__init__()
        self.password = password

    def run(self):
        is_compromised, count = self.check_password(self.password)
        self.result.emit(is_compromised, count)

    def check_password(self, password):
        sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix = sha1_password[:5]
        suffix = sha1_password[5:]

        url = f"{HIBP_API_URL}{prefix}"

        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                hashes = (line.split(':') for line in response.text.splitlines())
                for h, count in hashes:
                    if h == suffix:
                        return True, int(count)
                return False, 0
            elif response.status_code == 429:
                # Rate limit exceeded
                return False, 0
            else:
                return False, 0
        except requests.exceptions.RequestException:
            # Network error
            return False, 0
```

- **Purpose:** Contains the core functionalities for password evaluation, including strength calculation, compromised password checks, password generation, and providing content for resources, FAQs, and help sections.

- **Components:**
  - **PasswordEvaluator Class:** Implements methods for assessing password strength, evaluating policies, generating strong passwords, and retrieving content.
  - **PasswordCheckThread Class:** Handles asynchronous checks against the HIBP API to determine if a password has been compromised.

- **Features:**
  - **Entropy Calculation:** Uses mathematical computations to determine password strength.
  - **Policy Enforcement:** Ensures passwords meet user-defined requirements.
  - **Content Provision:** Supplies HTML-formatted content for various informational tabs.

### 4. Database Module (`database.py`)

```python
# database.py

import sqlite3
import datetime
from cryptography.fernet import Fernet

ENCRYPTION_KEY_FILE = 'encryption.key'

class PasswordDatabase:
    def __init__(self, frontend):
        self.frontend = frontend
        self.conn = None
        self.cursor = None
        self.cipher_suite = None

    def initDB(self):
        """
        Initialize the SQLite database for password history.
        """
        self.conn = sqlite3.connect("password_history.db")
        self.cursor = self.conn.cursor()
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS history
                            (password TEXT, date_added TEXT)''')
        self.conn.commit()
        self.cleanupOldPasswords()

    def initEncryption(self):
        """
        Initialize encryption for stored passwords.
        """
        try:
            # Check if encryption key exists
            with open(ENCRYPTION_KEY_FILE, 'rb') as key_file:
                key = key_file.read()
        except FileNotFoundError:
            # Generate a new key and save it
            key = Fernet.generate_key()
            with open(ENCRYPTION_KEY_FILE, 'wb') as key_file:
                key_file.write(key)
        self.cipher_suite = Fernet(key)

    def encryptPassword(self, password):
        """
        Encrypt the password using Fernet symmetric encryption.
        """
        encrypted_password = self.cipher_suite.encrypt(password.encode('utf-8'))
        return encrypted_password.decode('utf-8')

    def decryptPassword(self, encrypted_password):
        """
        Decrypt the password using Fernet symmetric encryption.
        """
        try:
            decrypted_password = self.cipher_suite.decrypt(encrypted_password.encode('utf-8')).decode('utf-8')
            return decrypted_password
        except:
            return "Decryption Error"

    def cleanupOldPasswords(self):
        """
        Delete passwords older than the expiration period from the history and ensure history size limit.
        """
        if self.frontend.password_expiration_days > 0:
            cutoff_date = datetime.datetime.now() - datetime.timedelta(days=self.frontend.password_expiration_days)
            self.cursor.execute("DELETE FROM history WHERE date_added < ?", (cutoff_date.strftime('%Y-%m-%d %H:%M:%S'),))
            self.conn.commit()

        # Enforce maximum history size
        self.enforceMaxHistorySize()

    def enforceMaxHistorySize(self):
        """
        Enforce the maximum password history size.
        """
        self.cursor.execute("SELECT COUNT(*) FROM history")
        count = self.cursor.fetchone()[0]
        if count > self.frontend.max_history_size:
            # Delete oldest entries
            excess = count - self.frontend.max_history_size
            self.cursor.execute("DELETE FROM history WHERE rowid IN (SELECT rowid FROM history ORDER BY date_added ASC LIMIT ?)", (excess,))
            self.conn.commit()

    def loadPasswordHistory(self):
        """
        Load password history from the database into the history list widget.
        """
        self.cleanupOldPasswords()
        self.frontend.gui.history_list.clear()
        self.cursor.execute("SELECT password, date_added FROM history ORDER BY date_added DESC")
        for row in self.cursor.fetchall():
            decrypted_password = self.decryptPassword(row[0])
            self.frontend.gui.history_list.addItem(f"{decrypted_password} (Added on {row[1]})")

    def savePasswordHistory(self, password):
        """
        Save the generated password to the history database after encryption.
        """
        encrypted_password = self.encryptPassword(password)
        date_added = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.cursor.execute("INSERT INTO history (password, date_added) VALUES (?, ?)", (encrypted_password, date_added))
        self.conn.commit()
        self.enforceMaxHistorySize()

    def close(self):
        if self.conn:
            self.conn.close()
```

- **Purpose:** Manages the SQLite database for storing encrypted password histories and handles encryption and decryption processes.

- **Components:**
  - **Database Connection:** Establishes and manages a connection to the SQLite database.
  - **Encryption Mechanism:** Uses Fernet symmetric encryption to secure stored passwords.

- **Features:**
  - **Data Persistence:** Ensures password histories are retained across sessions.
  - **Security:** Encrypts all stored passwords to protect user data.
  - **Policy Enforcement:** Deletes old passwords based on user-defined expiration settings and history size limits.

### 5. Main Script (`main.py`)

```python
# main.py

import sys
from PyQt6.QtWidgets import QApplication
from gui import PasswordQualityCheckerGUI
from frontend import PasswordQualityCheckerFrontend

def main():
    app = QApplication(sys.argv)
    frontend = PasswordQualityCheckerFrontend(None)
    gui = PasswordQualityCheckerGUI(frontend)
    frontend.gui = gui
    frontend.database.loadPasswordHistory()
    gui.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
```

- **Purpose:** Initializes the application, creates instances of the GUI and front-end logic, and starts the event loop.

- **Process:**
  - **Application Initialization:** Sets up the QApplication instance.
  - **Component Instantiation:** Creates instances of the frontend logic and GUI, linking them together.
  - **History Loading:** Loads the password history into the GUI upon startup.
  - **Event Loop:** Starts the application's event loop to await user interactions.

---

## Installation and Setup

To set up and run the **Password Quality Checker** application, follow the steps below:

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/AshleyMGreerProjects/SE-480---Password-Quality-Checker.git
   cd SE-480---Password-Quality-Checker/PQC
   ```

2. **Create a Virtual Environment (Recommended):**

   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install Dependencies:**

   Ensure you have Python 3.8 or higher installed. Install the required Python packages using `pip`:

   ```bash
   pip install -r requirements.txt
   ```

   **`requirements.txt` Content:**

   ```
   PyQt6==6.5.2
   requests==2.31.0
   cryptography==41.0.3
   ```

4. **Run the Application:**

   ```bash
   python main.py
   ```

   *Ensure you are inside the `PQC` folder when running the application.*

### Converting the Application into an Executable

To distribute the **Password Quality Checker** as a standalone Windows executable (`.exe`), you can use **PyInstaller**. This allows users to run the application without needing to install Python or any dependencies.

**Steps to Create an Executable:**

1. **Install PyInstaller:**

   ```bash
   pip install pyinstaller
   ```

2. **Navigate to the Application Directory:**

   ```bash
   cd path_to_your_application_directory/PQC
   ```

3. **Create the Executable:**

   Run PyInstaller with the following options to create a one-file executable without a console window:

   ```bash
   pyinstaller --onefile --windowed main.py
   ```

4. **Locate the Executable:**

   After PyInstaller finishes, the executable `main.exe` will be located in the `dist` directory within your application folder.

---

## Usage Guide

Upon launching the **Password Quality Checker**, users are greeted with a sleek, black-themed interface divided into several tabs, each serving a distinct purpose.

### 1. **Password Checker Tab**

- **Enter Password:** Input the password you wish to evaluate.
- **Strength Meter:** Observe real-time feedback on password strength as you type.
- **Show Password:** Toggle to view or hide your entered password.
- **Check Password Strength:** Click to initiate the evaluation and compromised password check.
- **Output Area:** View detailed feedback based on the evaluation.
- **Clear Output:** Reset the feedback area.
- **Copy Suggested Password:** If your password is weak or compromised, a strong password suggestion is provided, which can be copied directly to your clipboard.

### 2. **Resources Tab**

- **Select a Resource:** Choose from a dropdown menu to access detailed guidelines and best practices.
- **Display Area:** Read comprehensive information on selected topics such as NIST guidelines, OWASP policies, password managers, and more.

### 3. **FAQ Tab**

- **Browse FAQs:** Find answers to common questions related to password security and application functionalities.

### 4. **Password History Tab**

- **View History:** Review previously generated passwords along with the dates they were added.
- **Export History:** Save your password history to a text file for record-keeping or auditing purposes.

### 5. **Options Tab**

- **Customize Password Policies:**
  - **Length Settings:** Define minimum and maximum password lengths.
  - **Character Requirements:** Enforce the inclusion of uppercase letters, lowercase letters, digits, and special characters.
  - **Compromised Password Check:** Enable or disable the feature that checks if passwords have been compromised.
  - **Password History Settings:** Set the maximum number of password entries to retain.
  - **Password Expiration Policy:** Determine the frequency (in days) at which passwords should be updated.

### 6. **Help Tab**

- **Guidance:** Access instructions on navigating and utilizing the application's features.
- **Tips:** Learn best practices for effective password management.
- **Support:** Contact information for user assistance.

---

## Testing and Validation

Throughout a rigorous two-week development cycle, the **Password Quality Checker** underwent extensive testing to ensure reliability, security, and user satisfaction.

### 1. **Unit Testing**

- **Password Evaluation:** Verified that the strength meter accurately reflects password complexity and entropy.
- **API Interaction:** Ensured that compromised password checks interact correctly with the HIBP API, handling responses and rate limits appropriately.
- **Password Generation:** Tested the randomness and compliance of generated passwords with user-defined policies.
- **Encryption:** Confirmed that password histories are encrypted and decrypted correctly, safeguarding user data.
- **Settings Management:** Validated that user preferences persist across sessions and are correctly applied.

### 2. **Integration Testing**

- **End-to-End Flow:** Simulated user interactions from password entry to history management, ensuring seamless transitions and data integrity.
- **Error Handling:** Tested the application's resilience against network failures, API rate limiting, and invalid inputs, ensuring graceful degradation and informative feedback.

### 3. **User Acceptance Testing (UAT)**

- **Usability:** Gathered feedback on the intuitive design and navigability of the UI.
- **Functionality:** Ensured that all features operate as intended, providing users with accurate and helpful information.

### 4. **Security Testing**

- **Data Protection:** Verified that all stored passwords are encrypted and inaccessible in plaintext.
- **API Security:** Confirmed that only partial hashes are sent to the HIBP API, maintaining user privacy.
- **Clipboard Handling:** Ensured that copied passwords do not linger longer than necessary in the system clipboard.

---

## Future Enhancements

While the current version of the **Password Quality Checker** offers robust features, several enhancements are planned to further elevate its utility and security:

1. **Multi-Language Support:** Expand the application's accessibility by supporting multiple languages.
2. **Advanced Reporting:** Provide detailed analytics on password strengths and compromise statistics over time.
3. **Integration with Password Managers:** Facilitate seamless synchronization with popular password management tools.
4. **Biometric Authentication:** Incorporate biometric verification methods for enhanced security.
5. **Cloud Backup:** Offer encrypted cloud storage options for password histories, ensuring data redundancy.
6. **Custom Policy Templates:** Allow organizations to define and share password policy templates tailored to their security requirements.

---

## Conclusion

The **Password Quality Checker** stands as a testament to diligent development and a commitment to enhancing user security. Through its comprehensive feature set, user-centric design, and robust security measures, it empowers individuals and organizations to manage their passwords effectively, safeguarding against potential breaches and vulnerabilities. The meticulous two-week development process ensured that every aspect of the application meets high standards of functionality, security, and usability.

---

## Appendix

### Dependencies

Ensure that the following Python packages are installed:

- **PyQt6:** For building the graphical user interface.
- **requests:** For handling HTTP requests to the HIBP API.
- **cryptography:** For encrypting and decrypting stored password histories.

**Installation via pip:**

```bash
pip install PyQt6==6.5.2 requests==2.31.0 cryptography==41.0.3
```

Alternatively, if a `requirements.txt` file is provided, install all dependencies at once:

```bash
pip install -r requirements.txt
```

**`requirements.txt` Content:**

```
PyQt6==6.5.2
requests==2.31.0
cryptography==41.0.3
```

*Note:* Including specific version numbers ensures compatibility and stability. Adjust the versions as needed based on your development environment.

### License

The **Password Quality Checker** application is licensed under the [MIT License](https://opensource.org/licenses/MIT).

**MIT License**

```
MIT License

Copyright (c) 2024 Ashley M. Greer

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software. THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
```

---

**Repository Link:** [SE-480 --- Password Quality Checker](https://github.com/AshleyMGreerProjects/SE-480---Password-Quality-Checker)

For any additional information, updates, or contributions, please visit the [GitHub repository](https://github.com/AshleyMGreerProjects/SE-480---Password-Quality-Checker).
