# Ransomware Detection Tool
&nbsp;
&nbsp;

## Overview
The **Ransomware Detection Tool** is a comprehensive Python application designed to detect, simulate, and respond to ransomware threats effectively. With a user-friendly graphical interface, this tool integrates various functionalities aimed at safeguarding user data against malicious encryption attacks. It combines traditional detection methods with advanced AI techniques to provide a robust defense mechanism.
&nbsp;
&nbsp;

## Features
### 1. File Encryption and Decryption
- **Secure Encryption**: Utilizes the `cryptography` library to encrypt files using symmetric encryption (Fernet). This ensures that sensitive data is protected from unauthorized access.
- **User -Friendly Interface**: The GUI allows users to easily select files for encryption and decryption, providing a seamless experience.
&nbsp;
&nbsp;

### 2. Ransomware Simulation
- **Testing Environment**: Simulate ransomware behavior by creating and encrypting dummy files. This feature is useful for testing the detection capabilities of the tool without risking actual data.
- **Educational Purpose**: Helps users understand how ransomware operates and the importance of data protection.
&nbsp;
&nbsp;

### 3. USB Device Monitoring
- **Continuous Monitoring**: The tool actively monitors USB devices for suspicious files with known ransomware extensions (e.g., `.locked`, `.encrypted`).
- **Quarantine Mechanism**: Automatically quarantines any detected suspicious files to prevent potential spread and damage.
&nbsp;
&nbsp;

### 4. File Integrity Monitoring
- **Hash Comparison**: Monitors specified files for unauthorized modifications by computing and comparing cryptographic hashes (MD5). This ensures that files remain unchanged and secure.
- **Alert System**: Notifies users if any integrity violations are detected, allowing for immediate action.
&nbsp;
&nbsp;

### 5. Threat Report Generation
- **Detailed Reporting**: Generates comprehensive PDF reports summarizing detected threats, actions taken, and system activities during the session.
- **Customizable Output**: Users can choose where to save the report, making it easy to keep records of security events.
&nbsp;
&nbsp;

### 6. AI-Powered Detection
- **Machine Learning Integration**: Utilizes a pre-trained AI model to analyze file attributes (e.g., file size, entropy) for potential ransomware threats.
- **Predictive Analysis**: Enhances detection capabilities beyond traditional signature-based methods, allowing for the identification of new and evolving threats.
&nbsp;
&nbsp;

### 7. User Authentication
- **Secure Decryption**: Requires user authentication before allowing file decryption, simulating a ransom payment scenario. This feature emphasizes the importance of security and user awareness.
- **Customizable Password**: The authentication mechanism can be easily modified to enhance security.
&nbsp;
&nbsp;

### 8. Real-Time Directory Monitoring
- **Activity Tracking**: Monitors specified directories for file creations, modifications, and deletions, providing real-time alerts for suspicious activities.
- **Immediate Response**: Allows users to take prompt action against potential threats.
&nbsp;
&nbsp;

### 9. Process Behavior Monitoring
- **Resource Usage Analysis**: Monitors system processes for abnormal CPU or memory usage, which may indicate malicious activity.
- **Alert Notifications**: Notifies users of suspicious processes, enabling proactive threat management.
&nbsp;
&nbsp;

## Installation
&nbsp;
&nbsp;

### Prerequisites
Before installing the Ransomware Detection Tool, ensure you have the following:
- **Python 3.x**: The application is built using Python, so you need to have Python installed on your system.
- **Required Libraries**: The following libraries must be installed for the application to function correctly:
  - `cryptography`
  - `psutil`
  - `watchdog`
  - `ttkbootstrap`
  - `Pillow`
  - `pygame`
  - `reportlab`
  - `numpy`
&nbsp;
&nbsp;

### Steps to Install
1. **Clone the Repository**: Open your terminal or command prompt and run the following command to clone the repository:
   ```bash
   git clone https://github.com/yourusername/ransomware-detection-tool.git
   cd ransomware-detection-tool
