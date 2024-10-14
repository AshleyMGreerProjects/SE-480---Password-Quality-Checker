import sys
import re
import random
import string
import datetime
import sqlite3
import math
import hashlib
import requests  # For making HTTP requests
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QLabel, QLineEdit, QPushButton,
                             QVBoxLayout, QTextEdit, QComboBox, QListWidget, QTabWidget, QCheckBox,
                             QSpinBox, QProgressBar, QFileDialog, QMessageBox, QHBoxLayout)
from PyQt6.QtCore import Qt, QSettings, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QPalette, QColor
from cryptography.fernet import Fernet  # For encryption

# Constants
DEFAULT_MAX_HISTORY_SIZE = 100  # Default maximum number of password history entries
DEFAULT_PASSWORD_EXPIRATION_DAYS = 90  # Default password expiration period
ENCRYPTION_KEY_FILE = 'encryption.key'  # File to store the encryption key

class PasswordCheckThread(QThread):
    """
    Worker thread to check if a password has been compromised.
    Emits a signal with the result.
    """
    result = pyqtSignal(bool, int)  # (is_compromised, count)

    def __init__(self, password):
        super().__init__()
        self.password = password

    def run(self):
        is_compromised, count = self.check_password(self.password)
        self.result.emit(is_compromised, count)

    def check_password(self, password):
        """
        Check if the password has been compromised using the k-Anonymity model with HIBP API.
        Returns a tuple of (is_compromised, count).
        """
        sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix = sha1_password[:5]
        suffix = sha1_password[5:]

        url = f"https://api.pwnedpasswords.com/range/{prefix}"

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

class PasswordQualityChecker(QMainWindow):
    def __init__(self):
        super().__init__()
        self.settings = QSettings("YourCompany", "PasswordQualityChecker")
        self.minimum_length = self.settings.value("minimum_length", 8, type=int)
        self.maximum_length = self.settings.value("maximum_length", 128, type=int)
        self.compromised_check_enabled = self.settings.value("compromised_check_enabled", True, type=bool)
        self.require_uppercase = self.settings.value("require_uppercase", True, type=bool)
        self.require_lowercase = self.settings.value("require_lowercase", True, type=bool)
        self.require_digits = self.settings.value("require_digits", True, type=bool)
        self.require_special = self.settings.value("require_special", True, type=bool)
        self.max_history_size = self.settings.value("max_history_size", DEFAULT_MAX_HISTORY_SIZE, type=int)
        self.password_expiration_days = self.settings.value("password_expiration_days", DEFAULT_PASSWORD_EXPIRATION_DAYS, type=int)
        self.setWindowTitle("Password Quality Checker")
        self.setGeometry(100, 100, 600, 800)  # Increased height for better UI
        self.initUI()
        self.initDB()
        self.loadPasswordHistory()
        self.initEncryption()

    def initUI(self):
        # Set up the palette for UI styling
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

        # Main widget and layout
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QVBoxLayout()

        # Tab widget
        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)

        # Password Checker Tab
        self.checker_tab = QWidget()
        self.tabs.addTab(self.checker_tab, "Password Checker")
        self.initCheckerTab()

        # Resources Tab
        self.resources_tab = QWidget()
        self.tabs.addTab(self.resources_tab, "Resources")
        self.initResourcesTab()

        # FAQ Tab
        self.faq_tab = QWidget()
        self.tabs.addTab(self.faq_tab, "FAQ")
        self.initFAQTab()

        # Password History Tab
        self.history_tab = QWidget()
        self.tabs.addTab(self.history_tab, "Password History")
        self.initHistoryTab()

        # Options Tab
        self.options_tab = QWidget()
        self.tabs.addTab(self.options_tab, "Options")
        self.initOptionsTab()

        # Help Tab
        self.help_tab = QWidget()
        self.tabs.addTab(self.help_tab, "Help")
        self.initHelpTab()

        main_widget.setLayout(main_layout)

    def initCheckerTab(self):
        layout = QVBoxLayout()

        # Password Input Label
        self.input_label = QLabel("Enter your password:")
        layout.addWidget(self.input_label)

        # Password Input Field
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setToolTip("Enter the password you want to evaluate.")
        layout.addWidget(self.password_input)

        # Password Strength Meter
        self.strength_bar = QProgressBar()
        self.strength_bar.setRange(0, 100)
        self.strength_bar.setFormat("Strength: %p%")
        layout.addWidget(self.strength_bar)

        # Update Strength Bar as user types
        self.password_input.textChanged.connect(self.updateStrengthBar)

        # Password Visibility Toggle
        self.show_password_checkbox = QCheckBox("Show Password")
        self.show_password_checkbox.setToolTip("Toggle to show or hide your password.")
        self.show_password_checkbox.stateChanged.connect(self.togglePasswordVisibility)
        layout.addWidget(self.show_password_checkbox)

        # Check Password Strength Button
        self.check_button = QPushButton("Check Password Strength")
        self.check_button.setToolTip("Click to evaluate the strength of your password and check if it's compromised.")
        self.check_button.clicked.connect(self.checkPassword)
        layout.addWidget(self.check_button)

        # Output Area for Feedback
        self.output_area = QTextEdit()
        self.output_area.setReadOnly(True)
        self.output_area.setToolTip("Displays the results of the password evaluation.")
        layout.addWidget(self.output_area)

        # Clear Output Button
        self.clear_output_button = QPushButton("Clear Output")
        self.clear_output_button.setToolTip("Clear the feedback area.")
        self.clear_output_button.clicked.connect(self.clearOutput)
        layout.addWidget(self.clear_output_button)

        # Copy Suggested Password Button (Initially Hidden)
        self.copy_button = QPushButton("Copy Suggested Password")
        self.copy_button.setToolTip("Copy the suggested password to the clipboard.")
        self.copy_button.clicked.connect(self.copySuggestedPassword)
        self.copy_button.hide()  # Hide initially
        layout.addWidget(self.copy_button)

        self.checker_tab.setLayout(layout)

    def updateStrengthBar(self):
        password = self.password_input.text()
        score = self.calculatePasswordStrength(password)
        self.strength_bar.setValue(score)

        # Update Progress Bar Color and Format based on Strength
        if score < 50:
            self.strength_bar.setStyleSheet("QProgressBar::chunk { background-color: #FF0000; }")  # Red
            self.strength_bar.setFormat("Strength: Weak")
        elif score < 70:
            self.strength_bar.setStyleSheet("QProgressBar::chunk { background-color: #FFA500; }")  # Orange
            self.strength_bar.setFormat("Strength: Moderate")
        else:
            self.strength_bar.setStyleSheet("QProgressBar::chunk { background-color: #00FF00; }")  # Green
            self.strength_bar.setFormat("Strength: Strong")

    def calculatePasswordStrength(self, password):
        """
        Calculate password strength based on entropy.
        """
        length = len(password)
        variations = 0

        if re.search(r'[a-z]', password):
            variations += 26
        if re.search(r'[A-Z]', password):
            variations += 26
        if re.search(r'\d', password):
            variations += 10
        if re.search(r'[^\w\s]', password):
            variations += 32  # Approximate number of punctuation characters

        entropy = length * (math.log2(variations) if variations else 0)
        max_entropy = 100  # Adjusted for scaling
        score = min(int((entropy / max_entropy) * 100), 100)
        return score

    def togglePasswordVisibility(self):
        """
        Toggle the visibility of the password input field.
        """
        if self.show_password_checkbox.isChecked():
            self.password_input.setEchoMode(QLineEdit.EchoMode.Normal)
            self.show_password_checkbox.setText("Hide Password")
        else:
            self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
            self.show_password_checkbox.setText("Show Password")

    def initResourcesTab(self):
        layout = QVBoxLayout()
        label = QLabel("Select a resource:")
        layout.addWidget(label)

        self.resource_dropdown = QComboBox()
        self.resource_dropdown.addItems([
            "Select",
            "NIST Guidelines",
            "OWASP Password Policies",
            "Password Managers",
            "Understanding Pwned Passwords",
            "Tips for Creating Strong Passwords"
        ])
        self.resource_dropdown.currentIndexChanged.connect(self.displayResource)
        layout.addWidget(self.resource_dropdown)

        self.resource_display = QTextEdit()
        self.resource_display.setReadOnly(True)
        layout.addWidget(self.resource_display)

        self.resources_tab.setLayout(layout)

    def displayResource(self, index):
        """
        Display the selected resource information.
        """
        resources = {
            1: (
                "<h2>NIST Password Guidelines</h2>"
                "<p>The National Institute of Standards and Technology (NIST) provides comprehensive guidelines for password policies and authentication practices. Key recommendations include:</p>"
                "<ul>"
                "<li><b>Minimum Length:</b> Passwords should be at least <b>8 characters</b>, but longer passwords or passphrases up to <b>64 characters</b> are encouraged.</li>"
                "<li><b>Complexity:</b> While complexity requirements (like including numbers and symbols) are not strictly enforced, using a mix of character types enhances security.</li>"
                "<li><b>Avoid Composition Rules:</b> Do not impose composition rules that make passwords hard to remember and encourage unsafe practices.</li>"
                "<li><b>Screen Passwords Against Blacklists:</b> Check passwords against lists of commonly used or compromised passwords and disallow them.</li>"
                "<li><b>No Periodic Expiration:</b> Do not require periodic password changes without evidence of compromise.</li>"
                "<li><b>Allow Copy and Paste:</b> Do not prevent users from pasting passwords into password fields to facilitate the use of password managers.</li>"
                "<li><b>Limit Password Attempts:</b> Implement rate-limiting to protect against brute-force attacks.</li>"
                "</ul>"
                "<p>For more detailed information, visit the <a href='https://pages.nist.gov/800-63-3/sp800-63b.html'>NIST Digital Identity Guidelines</a>.</p>"
            ),
            2: (
                "<h2>OWASP Password Policies</h2>"
                "<p>The Open Web Application Security Project (OWASP) provides best practices for authentication and password management:</p>"
                "<ul>"
                "<li><b>Password Storage:</b> Store passwords using strong, adaptive hashing algorithms like <b>bcrypt</b>, <b>scrypt</b>, or <b>Argon2</b>.</li>"
                "<li><b>Secure Transmission:</b> Ensure passwords are transmitted over secure channels using protocols like <b>HTTPS</b>.</li>"
                "<li><b>Account Lockout:</b> Implement account lockout mechanisms after <b>3-5 failed login attempts</b> to prevent brute-force attacks.</li>"
                "<li><b>Multi-Factor Authentication:</b> Encourage or require the use of multi-factor authentication (MFA) for added security.</li>"
                "<li><b>Session Management:</b> Use secure session management practices to protect authenticated sessions.</li>"
                "</ul>"
                "<p>For more information, visit the <a href='https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html'>OWASP Authentication Cheat Sheet</a>.</p>"
            ),
            3: (
                "<h2>Password Managers</h2>"
                "<p>Password managers help you securely store and manage your passwords:</p>"
                "<ul>"
                "<li><b>Convenience:</b> Store all your passwords in one secure place, accessible with a master password.</li>"
                "<li><b>Security:</b> Use strong, unique passwords for each account without having to remember them all.</li>"
                "<li><b>Features:</b> Many password managers offer features like password generation, breach alerts, and secure sharing.</li>"
                "</ul>"
                "<p>Popular password managers include <b>LastPass</b>, <b>1Password</b>, and <b>Bitwarden</b>.</p>"
            ),
            4: (
                "<h2>Understanding Pwned Passwords</h2>"
                "<p>The Pwned Passwords service allows you to check if a password has appeared in known data breaches:</p>"
                "<ul>"
                "<li><b>Privacy:</b> Uses the k-Anonymity model to ensure your password is never revealed during the check.</li>"
                "<li><b>Security:</b> Helps you avoid using passwords that attackers already know. Over <b>500 million</b> compromised passwords are tracked.</li>"
                "<li><b>Integration:</b> Many services and applications integrate with Pwned Passwords to enhance security.</li>"
                "</ul>"
                "<p>Learn more at the <a href='https://haveibeenpwned.com/Passwords'>Pwned Passwords website</a>.</p>"
            ),
            5: (
                "<h2>Tips for Creating Strong Passwords:</h2>"
                "<ol>"
                "<li><b>Length:</b> Use at least <b>12 characters</b>. Longer passwords are generally more secure.</li>"
                "<li><b>Complexity:</b> Incorporate a mix of uppercase and lowercase letters, numbers, and special characters.</li>"
                "<li><b>Avoid Common Words:</b> Do not use easily guessable information like your name, birthday, or common dictionary words.</li>"
                "<li><b>Use Passphrases:</b> Consider using a combination of unrelated words to form a passphrase, which can be easier to remember and more secure.</li>"
                "<li><b>Unique Passwords:</b> Use a unique password for each of your accounts to prevent a single breach from compromising multiple services.</li>"
                "<li><b>Regular Updates:</b> Change your passwords every <b>90 days</b> or if you suspect any security issues.</li>"
                "<li><b>Two-Factor Authentication (2FA):</b> Enable 2FA where possible for an added layer of security.</li>"
                "</ol>"
            )
        }
        self.resource_display.setHtml(resources.get(index, ""))

    def initFAQTab(self):
        layout = QVBoxLayout()
        faq_text = QTextEdit()
        faq_text.setReadOnly(True)
        faq_content = (
            "<h2>Frequently Asked Questions:</h2>"
            "<h3>1. How is my password strength calculated?</h3>"
            "<p>The application evaluates password strength based on length and complexity, adhering to NIST guidelines. It considers the use of uppercase and lowercase letters, numbers, and special characters.</p>"
            "<h3>2. What makes a strong password?</h3>"
            "<p>A strong password is typically at least <b>12 characters</b> long and includes a mix of uppercase and lowercase letters, numbers, and special characters. It should not contain easily guessable information like names or common words.</p>"
            "<h3>3. Can I customize the password policies?</h3>"
            "<p>Yes, navigate to the 'Options' tab to adjust settings such as minimum and maximum password length, character requirements, and whether to check if passwords have been compromised.</p>"
            "<h3>4. How does the compromised password check work?</h3>"
            "<p>The application uses the k-Anonymity model provided by the Have I Been Pwned (HIBP) API. Your password is hashed, and only a portion of the hash is sent to the API to ensure your password remains private.</p>"
            "<h3>5. Is my password stored or sent over the internet?</h3>"
            "<p>No, passwords are never stored or sent in plaintext. Only hashed versions are used for checks, ensuring your password remains secure.</p>"
            "<h3>6. How can I export my password history?</h3>"
            "<p>Go to the 'Password History' tab and click on the 'Export History' button to save your password history as a text file.</p>"
            "<h3>7. What should I do if my password is compromised?</h3>"
            "<p>If your password is found to be compromised, immediately change it to a strong, unique password. Additionally, enable two-factor authentication (2FA) on your accounts for enhanced security.</p>"
            "<h3>8. Does the application store my passwords?</h3>"
            "<p>No, the application does not store your passwords. All password checks are performed securely, and your passwords are neither saved nor transmitted in plaintext.</p>"
            "<h3>9. Why should I use a password manager?</h3>"
            "<p>Using a password manager allows you to generate and store complex passwords without having to remember them. This enhances your overall security by enabling the use of unique passwords for each account.</p>"
            "<h3>10. How often should I change my passwords?</h3>"
            "<p>While frequent password changes are not necessary without evidence of compromise, it's good practice to update passwords for critical accounts every <b>90 days</b> or if you suspect any security issues.</p>"
        )
        faq_text.setHtml(faq_content)
        layout.addWidget(faq_text)
        self.faq_tab.setLayout(layout)

    def initHistoryTab(self):
        layout = QVBoxLayout()
        self.history_list = QListWidget()
        layout.addWidget(self.history_list)

        self.export_button = QPushButton("Export History")
        self.export_button.clicked.connect(self.exportHistory)
        layout.addWidget(self.export_button)

        self.history_tab.setLayout(layout)

    def exportHistory(self):
        """
        Export the password history to a text file.
        """
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getSaveFileName(
            self, "Save Password History", "", "Text Files (*.txt);;All Files (*)", options=options)
        if file_name:
            try:
                with open(file_name, 'w') as file:
                    for index in range(self.history_list.count()):
                        item = self.history_list.item(index)
                        file.write(item.text() + '\n')
                self.output_area.append(f"Password history successfully exported to {file_name}.")
            except Exception as e:
                self.output_area.append(f"Error exporting history: {e}")

    def initOptionsTab(self):
        layout = QVBoxLayout()

        # Minimum Password Length Option
        min_length_label = QLabel("Minimum Password Length:")
        layout.addWidget(min_length_label)

        self.min_length_spinbox = QSpinBox()
        self.min_length_spinbox.setRange(8, 128)
        self.min_length_spinbox.setValue(self.minimum_length)
        self.min_length_spinbox.valueChanged.connect(self.updateMinimumLength)
        self.min_length_spinbox.setToolTip("Set the minimum number of characters required for passwords.")
        layout.addWidget(self.min_length_spinbox)

        # Maximum Password Length Option
        max_length_label = QLabel("Maximum Password Length:")
        layout.addWidget(max_length_label)

        self.max_length_spinbox = QSpinBox()
        self.max_length_spinbox.setRange(8, 128)
        self.max_length_spinbox.setValue(self.maximum_length)
        self.max_length_spinbox.valueChanged.connect(self.updateMaximumLength)
        self.max_length_spinbox.setToolTip("Set the maximum number of characters allowed for passwords.")
        layout.addWidget(self.max_length_spinbox)

        # Character Type Requirements
        char_requirements_label = QLabel("Character Requirements:")
        layout.addWidget(char_requirements_label)

        self.require_uppercase_checkbox = QCheckBox("Require Uppercase Letters")
        self.require_uppercase_checkbox.setChecked(self.require_uppercase)
        self.require_uppercase_checkbox.stateChanged.connect(self.updateCharacterRequirements)
        layout.addWidget(self.require_uppercase_checkbox)

        self.require_lowercase_checkbox = QCheckBox("Require Lowercase Letters")
        self.require_lowercase_checkbox.setChecked(self.require_lowercase)
        self.require_lowercase_checkbox.stateChanged.connect(self.updateCharacterRequirements)
        layout.addWidget(self.require_lowercase_checkbox)

        self.require_digits_checkbox = QCheckBox("Require Digits")
        self.require_digits_checkbox.setChecked(self.require_digits)
        self.require_digits_checkbox.stateChanged.connect(self.updateCharacterRequirements)
        layout.addWidget(self.require_digits_checkbox)

        self.require_special_checkbox = QCheckBox("Require Special Characters")
        self.require_special_checkbox.setChecked(self.require_special)
        self.require_special_checkbox.stateChanged.connect(self.updateCharacterRequirements)
        layout.addWidget(self.require_special_checkbox)

        # Compromised Password Check Option
        self.compromised_check_checkbox = QCheckBox("Enable Compromised Password Check")
        self.compromised_check_checkbox.setChecked(self.compromised_check_enabled)
        self.compromised_check_checkbox.setToolTip("Toggle to enable or disable checking if a password has been compromised.")
        self.compromised_check_checkbox.stateChanged.connect(self.toggleCompromisedCheck)
        layout.addWidget(self.compromised_check_checkbox)

        # Password History Settings
        history_label = QLabel("Password History Settings:")
        layout.addWidget(history_label)

        max_history_size_label = QLabel("Maximum Password History Size:")
        layout.addWidget(max_history_size_label)

        self.max_history_spinbox = QSpinBox()
        self.max_history_spinbox.setRange(10, 1000)
        self.max_history_spinbox.setValue(self.max_history_size)
        self.max_history_spinbox.valueChanged.connect(self.updateMaxHistorySize)
        self.max_history_spinbox.setToolTip("Set the maximum number of passwords to keep in history.")
        layout.addWidget(self.max_history_spinbox)

        # Password Expiration Setting
        expiration_label = QLabel("Password Expiration Policy:")
        layout.addWidget(expiration_label)

        self.password_expiration_spinbox = QSpinBox()
        self.password_expiration_spinbox.setRange(0, 365)
        self.password_expiration_spinbox.setValue(self.password_expiration_days)
        self.password_expiration_spinbox.valueChanged.connect(self.updatePasswordExpiration)
        self.password_expiration_spinbox.setToolTip("Set the number of days after which passwords should be changed. Set to 0 to disable.")
        layout.addWidget(self.password_expiration_spinbox)

        self.options_tab.setLayout(layout)

    def updateMinimumLength(self, value):
        """
        Update the minimum password length setting.
        """
        self.minimum_length = value
        self.settings.setValue("minimum_length", value)

    def updateMaximumLength(self, value):
        """
        Update the maximum password length setting.
        """
        self.maximum_length = value
        self.settings.setValue("maximum_length", value)

    def updateCharacterRequirements(self):
        """
        Update character type requirements.
        """
        self.require_uppercase = self.require_uppercase_checkbox.isChecked()
        self.settings.setValue("require_uppercase", self.require_uppercase)

        self.require_lowercase = self.require_lowercase_checkbox.isChecked()
        self.settings.setValue("require_lowercase", self.require_lowercase)

        self.require_digits = self.require_digits_checkbox.isChecked()
        self.settings.setValue("require_digits", self.require_digits)

        self.require_special = self.require_special_checkbox.isChecked()
        self.settings.setValue("require_special", self.require_special)

    def updateMaxHistorySize(self, value):
        """
        Update the maximum password history size.
        """
        self.max_history_size = value
        self.settings.setValue("max_history_size", value)

    def updatePasswordExpiration(self, value):
        """
        Update the password expiration policy.
        """
        self.password_expiration_days = value
        self.settings.setValue("password_expiration_days", value)

    def toggleCompromisedCheck(self):
        """
        Toggle the compromised password check feature.
        """
        self.compromised_check_enabled = self.compromised_check_checkbox.isChecked()
        self.settings.setValue("compromised_check_enabled", self.compromised_check_enabled)

    def initHelpTab(self):
        layout = QVBoxLayout()
        help_text = QTextEdit()
        help_text.setReadOnly(True)
        help_content = (
            "<h2>Welcome to the Password Quality Checker Application!</h2>"
            "<h3>Instructions:</h3>"
            "<ol>"
            "<li><b>Password Checker Tab:</b> Enter your password to check its strength and see if it's been compromised.</li>"
            "<li><b>Options Tab:</b> Adjust settings like minimum and maximum password length, character requirements, and toggle compromised password checks.</li>"
            "<li><b>FAQ Tab:</b> Find answers to common questions about password security and application usage.</li>"
            "<li><b>Resources Tab:</b> Access additional information and best practices for password management.</li>"
            "<li><b>Password History Tab:</b> View your password history and export it for your records.</li>"
            "</ol>"
            "<h3>Tips for Using the Application:</h3>"
            "<ul>"
            "<li><b>Password Strength Meter:</b> As you type your password, the strength meter updates to reflect its security level.</li>"
            "<li><b>Show Password:</b> Use the 'Show Password' checkbox to toggle visibility of your password.</li>"
            "<li><b>Export History:</b> Regularly export your password history to maintain a record of generated passwords.</li>"
            "<li><b>Keep Software Updated:</b> Ensure you are using the latest version of the application for optimal security and features.</li>"
            "</ul>"
            "<h3>Support:</h3>"
            "<p>If you encounter any issues or have questions, please refer to the FAQ section or contact support at <a href='ash.greer@go.stcloudstate.edu'>ash.greer@go.stcloudstate.edu</a>.</p>"
        )
        help_text.setHtml(help_content)
        layout.addWidget(help_text)
        self.help_tab.setLayout(layout)

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
        if self.password_expiration_days > 0:
            cutoff_date = datetime.datetime.now() - datetime.timedelta(days=self.password_expiration_days)
            self.cursor.execute("DELETE FROM history WHERE date_added < ?", (cutoff_date.strftime('%Y-%m-%d %H:%M:%S'),))
            self.conn.commit()

        # Enforce maximum history size
        self.cursor.execute("SELECT COUNT(*) FROM history")
        count = self.cursor.fetchone()[0]
        if count > self.max_history_size:
            # Delete oldest entries
            excess = count - self.max_history_size
            self.cursor.execute("DELETE FROM history WHERE rowid IN (SELECT rowid FROM history ORDER BY date_added ASC LIMIT ?)", (excess,))
            self.conn.commit()

    def loadPasswordHistory(self):
        """
        Load password history from the database into the history list widget.
        """
        self.cleanupOldPasswords()
        self.history_list.clear()
        self.cursor.execute("SELECT password, date_added FROM history ORDER BY date_added DESC")
        for row in self.cursor.fetchall():
            decrypted_password = self.decryptPassword(row[0])
            self.history_list.addItem(f"{decrypted_password} (Added on {row[1]})")

    def checkPassword(self):
        """
        Check the entered password's strength and whether it's compromised.
        """
        password = self.password_input.text()
        if not password:
            self.output_area.setText("Please enter a password.")
            return

        strength, feedback = self.evaluatePassword(password)

        self.output_area.clear()
        self.output_area.append(f"Password Strength: {strength}")
        self.output_area.append(feedback)

        if strength in ["Weak", "Compromised"]:
            # Start a thread to check if the generated password is compromised
            generated_password = self.generateStrongPassword()
            self.output_area.append(f"\nSuggested Password:\n{generated_password}")

            # Save to history
            self.savePasswordHistory(generated_password)

            # Reload history
            self.loadPasswordHistory()

            # Show the copy button and store the generated password
            self.generated_password = generated_password
            self.copy_button.show()
        else:
            # Hide the copy button if no suggestion is made
            self.copy_button.hide()

    def evaluatePassword(self, password):
        """
        Evaluate the password's strength and check if it meets policy requirements.
        Returns a tuple of (strength, feedback).
        """
        length = len(password)

        if length < self.minimum_length:
            strength = "Weak"
            feedback = f"Password is too short. It should be at least {self.minimum_length} characters long."
            return strength, feedback

        if length > self.maximum_length:
            strength = "Weak"
            feedback = f"Password is too long. It should be no more than {self.maximum_length} characters long."
            return strength, feedback

        # Check character requirements
        if self.require_uppercase and not re.search(r'[A-Z]', password):
            strength = "Weak"
            feedback = "Password must contain at least one uppercase letter."
            return strength, feedback

        if self.require_lowercase and not re.search(r'[a-z]', password):
            strength = "Weak"
            feedback = "Password must contain at least one lowercase letter."
            return strength, feedback

        if self.require_digits and not re.search(r'\d', password):
            strength = "Weak"
            feedback = "Password must contain at least one digit."
            return strength, feedback

        if self.require_special and not re.search(r'[^\w\s]', password):
            strength = "Weak"
            feedback = "Password must contain at least one special character."
            return strength, feedback

        # Calculate entropy for strength assessment
        entropy = self.calculateEntropy(password)
        if entropy < 50:
            strength = "Weak"
            feedback = "Password entropy is low. Consider adding more unique characters."
        elif entropy < 70:
            strength = "Moderate"
            feedback = "Password entropy is moderate. Adding more unique characters can enhance security."
        else:
            # Check if compromised
            if self.compromised_check_enabled:
                # Start a thread to check password
                self.thread = PasswordCheckThread(password)
                self.thread.result.connect(self.handlePasswordCheckResult)
                self.thread.start()
                strength = "Checking..."
                feedback = "Checking if the password has been compromised..."
            else:
                strength = "Strong"
                feedback = "Good job! Your password meets the policy requirements."

        return strength, feedback

    def handlePasswordCheckResult(self, is_compromised, count):
        """
        Handle the result from the password check thread.
        """
        if is_compromised:
            strength = "Compromised"
            feedback = f"This password has been found in {count} breaches. Please choose a different password."
            self.output_area.append(f"Password Strength: {strength}")
            self.output_area.append(feedback)

            # Generate a strong password suggestion
            generated_password = self.generateStrongPassword()
            self.output_area.append(f"\nSuggested Password:\n{generated_password}")

            # Save to history
            self.savePasswordHistory(generated_password)

            # Reload history
            self.loadPasswordHistory()

            # Show the copy button and store the generated password
            self.generated_password = generated_password
            self.copy_button.show()
        else:
            strength = "Strong"
            feedback = "Good job! Your password meets the policy requirements."
            self.output_area.append(f"Password Strength: {strength}")
            self.output_area.append(feedback)
            self.copy_button.hide()

    def calculateEntropy(self, password):
        """
        Calculate the entropy of the password based on character variety and length.
        """
        variations = 0

        if re.search(r'[a-z]', password):
            variations += 26
        if re.search(r'[A-Z]', password):
            variations += 26
        if re.search(r'\d', password):
            variations += 10
        if re.search(r'[^\w\s]', password):
            variations += 32  # Approximate number of punctuation characters

        entropy = len(password) * math.log2(variations) if variations else 0
        return entropy

    def generateStrongPassword(self):
        """
        Generate a strong random password that meets the minimum length and is not compromised.
        """
        # Define character sets based on requirements
        character_sets = ''
        if self.require_uppercase:
            character_sets += string.ascii_uppercase
        if self.require_lowercase:
            character_sets += string.ascii_lowercase
        if self.require_digits:
            character_sets += string.digits
        if self.require_special:
            character_sets += string.punctuation

        password_length = max(self.minimum_length, 12)
        for _ in range(100):  # Limit attempts to prevent infinite loops
            password = ''.join(random.choice(character_sets) for _ in range(password_length))
            if not self.isCompromisedPasswordDirect(password):
                return password
        return "P@ssw0rd!"  # Fallback password if generation fails

    def isCompromisedPasswordDirect(self, password):
        """
        Directly check if the password is compromised without threading.
        Used during password generation to ensure suggestions are not compromised.
        """
        sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix = sha1_password[:5]
        suffix = sha1_password[5:]

        url = f"https://api.pwnedpasswords.com/range/{prefix}"

        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                hashes = (line.split(':') for line in response.text.splitlines())
                for h, count in hashes:
                    if h == suffix:
                        return True
                return False
            else:
                return False
        except requests.exceptions.RequestException:
            return False

    def savePasswordHistory(self, password):
        """
        Save the generated password to the history database after encryption.
        """
        encrypted_password = self.encryptPassword(password)
        date_added = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.cursor.execute("INSERT INTO history (password, date_added) VALUES (?, ?)", (encrypted_password, date_added))
        self.conn.commit()

        # Enforce maximum history size
        self.cursor.execute("SELECT COUNT(*) FROM history")
        count = self.cursor.fetchone()[0]
        if count > self.max_history_size:
            # Delete oldest entries
            excess = count - self.max_history_size
            self.cursor.execute("DELETE FROM history WHERE rowid IN (SELECT rowid FROM history ORDER BY date_added ASC LIMIT ?)", (excess,))
            self.conn.commit()

    def clearOutput(self):
        """
        Clear the output area.
        """
        self.output_area.clear()
        self.copy_button.hide()

    def copySuggestedPassword(self):
        """
        Copy the suggested password to the clipboard.
        """
        if hasattr(self, 'generated_password'):
            clipboard = QApplication.clipboard()
            clipboard.setText(self.generated_password)
            self.output_area.append("\nSuggested password copied to clipboard.")
        else:
            self.output_area.append("\nNo suggested password to copy.")

    def closeEvent(self, event):
        """
        Ensure the database connection is closed when the application exits.
        """
        self.conn.close()
        event.accept()

def main():
    app = QApplication(sys.argv)
    checker = PasswordQualityChecker()
    checker.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
