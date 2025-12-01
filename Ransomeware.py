import os
import time
import hashlib
import logging
import psutil
import threading
import shutil
import tkinter as tk
from tkinter import messagebox, filedialog, scrolledtext
from cryptography.fernet import Fernet
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import ttkbootstrap as ttk
from PIL import Image, ImageTk  # Added for GIF animation
import winsound
import pickle
import numpy as np
import pygame

# Session start time for filtering logs in current session
SESSION_START_TIME = time.time()

# Logging setup
logging.basicConfig(filename="ransomware_detection.log", level=logging.INFO, format="%(asctime)s - %(message)s")

# Constants
KEY_FILE = "ransom_key.key"
QUARANTINE_FOLDER = "Quarantine"
BACKUP_FOLDER = "Backups"

# Generate & Load Encryption Key
def generate_key():
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as key_file:
        key_file.write(key)
    return key

def load_key():
    return open(KEY_FILE, "rb").read() if os.path.exists(KEY_FILE) else generate_key()

# Encrypt & Decrypt Files
def encrypt_file():
    file_path = filedialog.askopenfilename(filetypes=[("All Files", "*.*")])
    if not file_path:
        return
    backup_file(file_path)
    key = load_key()
    fernet = Fernet(key)

    # Create progress window
    progress_win = tk.Toplevel()
    progress_win.title("Encrypting File")
    progress_win.geometry("400x100")
    progress_win.resizable(False, False)
    ttk.Label(progress_win, text="Encrypting file, please wait...").pack(pady=10)
    progress_bar = ttk.Progressbar(progress_win, orient="horizontal", length=300, mode="indeterminate")
    progress_bar.pack(pady=10)
    progress_bar.start()

    try:
        with open(file_path, "rb") as file:
            data = file.read()
        encrypted_data = fernet.encrypt(data)
        with open(file_path, "wb") as file:
            file.write(encrypted_data)
        log_message(f"🔴 File Encrypted: {file_path}")
        messagebox.showinfo("Encryption Complete", "File encryption completed successfully.")
    except Exception as e:
        log_message(f"❌ Encryption failed: {e}")
        messagebox.showerror("Encryption Error", f"Failed to encrypt file: {e}")
    finally:
        progress_bar.stop()
        progress_win.destroy()
    # Removed show_ransom_note() call to disable ransom popup

def decrypt_file():
    file_path = filedialog.askopenfilename()
    if not file_path:
        return
    key = load_key()
    fernet = Fernet(key)
    try:
        with open(file_path, "rb") as file:
            decrypted_data = fernet.decrypt(file.read())
        with open(file_path, "wb") as file:
            file.write(decrypted_data)
        log_message(f"🟢 File Decrypted: {file_path}")
    except Exception as e:
        log_message(f"❌ Decryption failed: {e}")
        messagebox.showerror("Decryption Error", f"Failed to decrypt file: {e}")

# Log messages in GUI & Save Logs
def log_message(msg):
    log_text.configure(state='normal')
    log_text.insert(tk.END, msg + "\n")
    log_text.see(tk.END)
    log_text.configure(state='disabled')
    logging.info(msg)

# Quarantine System
def quarantine_file(file_path):
    os.makedirs(QUARANTINE_FOLDER, exist_ok=True)
    quarantined_file_path = os.path.join(QUARANTINE_FOLDER, os.path.basename(file_path))
    try:
        shutil.move(file_path, quarantined_file_path)
        log_message(f"⚠️ Suspicious file moved to quarantine: {quarantined_file_path}")
    except Exception as e:
        log_message(f"❌ Failed to quarantine file: {e}")

# Backup System
def backup_file(file_path):
    os.makedirs(BACKUP_FOLDER, exist_ok=True)
    backup_path = os.path.join(BACKUP_FOLDER, os.path.basename(file_path))
    try:
        shutil.copy(file_path, backup_path)
        log_message(f"🟡 File backed up: {backup_path}")
    except Exception as e:
        log_message(f"❌ Failed to backup file: {e}")

# Simulate Ransomware
def simulate_ransomware():
    simulation_dir = os.path.join(os.getcwd(), "Simulation_Files")
    os.makedirs(simulation_dir, exist_ok=True)
    dummy_files = ["doc1.txt", "photo.jpg", "report.pdf"]
    for fname in dummy_files:
        fpath = os.path.join(simulation_dir, fname)
        with open(fpath, "w") as f:
            f.write(f"This is dummy content for {fname}")
        log_message(f"📝 Created dummy file: {fpath}")
    key = load_key()
    fernet = Fernet(key)
    for fname in dummy_files:
        fpath = os.path.join(simulation_dir, fname)
        with open(fpath, "rb") as file:
            encrypted = fernet.encrypt(file.read())
        with open(fpath, "wb") as file:
            file.write(encrypted)
        log_message(f"🔐 Simulated encryption: {fpath}")
    log_message("✅ Ransomware simulation complete!")

# USB Device Monitoring
usb_monitoring = False
usb_monitor_thread = None

def monitor_usb_devices(start=True):
    global usb_monitoring, usb_monitor_thread
    if start:
        if usb_monitoring:
            return
        usb_monitoring = True
        initial_devices = set(psutil.disk_partitions())
        suspicious_ext = [".locked", ".encrypted", ".enc", ".cry", ".crypt"]
        def scan_usb_device(mountpoint):
            found = []
            for root_dir, _, files in os.walk(mountpoint):
                for file in files:
                    if any(file.endswith(ext) for ext in suspicious_ext):
                        full_path = os.path.join(root_dir, file)
                        found.append(full_path)
            if found:
                log_message(f"🔍 Suspicious files found on USB device {mountpoint}:\n" + "\n".join(found))
                for f in found:
                    quarantine_file(f)
            else:
                log_message(f"✅ No suspicious files found on USB device {mountpoint}")

        def usb_monitor():
            nonlocal initial_devices
            while usb_monitoring:
                time.sleep(5)
                current_devices = set(psutil.disk_partitions())
                new_devices = current_devices - initial_devices
                if new_devices:
                    for device in new_devices:
                        log_message(f"⚠️ ALERT: Unknown USB device detected: {device.device} mounted at {device.mountpoint}")
                        scan_usb_device(device.mountpoint)
                    initial_devices = current_devices
        usb_monitor_thread = threading.Thread(target=usb_monitor, daemon=True)
        usb_monitor_thread.start()
        log_message("🟢 USB Monitoring started...")
    else:
        if not usb_monitoring:
            return
        usb_monitoring = False
        log_message("🛑 USB Monitoring stopped.")

# File Integrity Monitoring
def monitor_file_integrity(file_path):
    try:
        initial_hash = hashlib.md5(open(file_path, "rb").read()).hexdigest()
    except Exception as e:
        log_message(f"❌ Error reading file: {e}")
        return
    def integrity_checker():
        while True:
            time.sleep(10)
            try:
                new_hash = hashlib.md5(open(file_path, "rb").read()).hexdigest()
                if initial_hash != new_hash:
                    log_message("⚠️ ALERT: File integrity compromised!")
                    quarantine_file(file_path)
                    return
            except:
                return
    threading.Thread(target=integrity_checker, daemon=True).start()
    log_message(f"🟢 File Integrity Monitoring started on {file_path}")

# Threat Report Generation
def generate_threat_report():
    import reportlab
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet
    import datetime

    log_file = "ransomware_detection.log"
    try:
        if not os.path.exists(log_file):
            log_message("❌ Error: Log file not found.")
            messagebox.showerror("Error", "No logs found to generate a report.")
            return
        with open(log_file, "r", encoding="utf-8") as logs:
            lines = logs.readlines()

        # Filter lines by session start time
        filtered_lines = []
        for line in lines:
            try:
                # Extract timestamp from log line (format: "YYYY-MM-DD HH:MM:SS,mmm - message")
                timestamp_str = line.split(" - ")[0]
                # Fix: parse milliseconds correctly by truncating after seconds
                timestamp_str_fixed = timestamp_str.split(",")[0]
                log_time = time.mktime(time.strptime(timestamp_str_fixed, "%Y-%m-%d %H:%M:%S"))
                if log_time >= SESSION_START_TIME:
                    filtered_lines.append(line.strip())
            except Exception:
                # If parsing fails, include the line anyway
                filtered_lines.append(line.strip())

        if not filtered_lines:
            filtered_lines = ["✅ No suspicious activity detected."]

        # Prepare data for table: headers + rows
        data = [["Timestamp", "Message", "Impact Status"]]
        styles = getSampleStyleSheet()
        for line in filtered_lines:
            # Parse timestamp and message
            if " - " in line:
                parts = line.split(" - ", 1)
                timestamp = parts[0]
                message = parts[1]
            else:
                timestamp = ""
                message = line

            # Determine impact status based on keywords in message
            impact = "No Threat"
            if any(k in message for k in ["High", "🔴", "⚠️"]) or "Suspicious" in message:
                impact = "Threat Found"
            elif any(k in message for k in ["Medium", "🟠"]):
                impact = "Threat Found"
            elif any(k in message for k in ["Low", "🟡"]):
                impact = "Threat Found"

            data.append([timestamp, message, impact])

        # Ask user for save location
        report_file = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF files", "*.pdf")], title="Save Threat Report As")
        if not report_file:
            log_message("⚠️ Threat report generation cancelled by user.")
            return

        # Create PDF document
        doc = SimpleDocTemplate(report_file, pagesize=letter)
        elements = []

        # Title
        title_style = styles["Title"]
        elements.append(Paragraph("📋 Threat Report", title_style))
        elements.append(Spacer(1, 12))

        # Create table
        table = Table(data, colWidths=[120, 300, 100])
        table_style = TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.darkgreen),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 14),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ])

        # Conditional row background colors based on impact status
        for i in range(1, len(data)):
            impact = data[i][2]
            if impact == "Threat Found":
                table_style.add('BACKGROUND', (0, i), (-1, i), colors.red)
                table_style.add('TEXTCOLOR', (0, i), (-1, i), colors.whitesmoke)
                # Set Impact Status cell text color to red
                table_style.add('TEXTCOLOR', (2, i), (2, i), colors.red)
            elif impact == "Medium":
                table_style.add('BACKGROUND', (0, i), (-1, i), colors.orange)
            elif impact == "Low":
                table_style.add('BACKGROUND', (0, i), (-1, i), colors.yellow)
            else:
                # Alternate row background colors for no threat rows
                if i % 2 == 0:
                    table_style.add('BACKGROUND', (0, i), (-1, i), colors.beige)
                else:
                    table_style.add('BACKGROUND', (0, i), (-1, i), colors.lightgrey)

        table.setStyle(table_style)
        elements.append(table)
        elements.append(Spacer(1, 12))

        # Impact summary
        impact_summary = "No significant threats detected."
        content_text = "\n".join(filtered_lines)
        if any(k in content_text for k in ["High", "🔴", "⚠️", "Threat Found"]):
            impact_summary = "Threats detected. Immediate action recommended."
        elif any(k in content_text for k in ["Medium", "🟠"]):
            impact_summary = "Medium threat level detected. Review and monitor closely."
        elif any(k in content_text for k in ["Low", "🟡"]):
            impact_summary = "Low threat level detected. Monitor the situation."

        impact_style = styles["Heading2"]
        elements.append(Paragraph("Impact Summary:", impact_style))
        elements.append(Paragraph(impact_summary, styles["Normal"]))
        elements.append(Spacer(1, 12))

        # Footer with generation time
        gen_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        footer_style = styles["Italic"]
        elements.append(Paragraph(f"Report Generated on: {gen_time}", footer_style))

        doc.build(elements)

        log_message(f"📑 Threat report generated successfully: {report_file}")
        messagebox.showinfo("Success", f"Threat report generated: {report_file}")
    except Exception as e:
        log_message(f"❌ Error generating report: {e}")
        messagebox.showerror("Error", f"Failed to generate report: {e}")

def detect_ransomware():
    try:
        import os
        log_message("🟢 Starting ransomware detection...")
        suspicious_ext = [".locked", ".encrypted", ".enc", ".cry", ".crypt"]
        found = []
        file_paths = filedialog.askopenfilenames(title="Select files to scan for ransomware")
        log_message(f"File dialog returned: {file_paths}")
        if not file_paths:
            log_message("⚠️ No files selected for ransomware detection.")
            threat_level_var.set("Threat Level: No Threat")
            threat_level_label.configure(foreground="green")
            return
        for file_path in file_paths:
            ext = os.path.splitext(file_path)[1].lower()
            log_message(f"Checking file: {file_path} with extension: {ext}")
            if ext in suspicious_ext:
                log_message(f"File {file_path} matched suspicious extension: {ext}")
                found.append(file_path)
        if found:
            log_message("🔴 Suspicious files detected:\n" + "\n".join(found))
            for f in found:
                quarantine_file(f)
            # Update threat level based on number of files found
            count = len(found)
            if count <= 3:
                threat_level_var.set("Threat Level: Low")
                threat_level_label.configure(foreground="yellow")
            elif count <= 6:
                threat_level_var.set("Threat Level: Medium")
                threat_level_label.configure(foreground="orange")
            else:
                threat_level_var.set("Threat Level: High")
                threat_level_label.configure(foreground="red")
            response = messagebox.askyesno("Ransomware Detected", "Ransomware files detected! Do you want to shutdown your system immediately?")
            if response:
                log_message("⚠️ User chose to shutdown the system due to ransomware detection.")
                os.system("shutdown /s /t 1")
            else:
                log_message("⚠️ User chose not to shutdown. Please remove ransomware files immediately.")
        else:
            log_message("✅ No ransomware signatures found in selected files.")
            threat_level_var.set("Threat Level: No Threat")
            threat_level_label.configure(foreground="green")
        log_message("🟢 Ransomware detection complete.")
    except Exception as e:
        log_message(f"❌ Error during ransomware detection: {e}")
        messagebox.showerror("Error", f"An error occurred during ransomware detection: {e}")

# Ransomware Signature Scanner
def ransomware_signature_scanner():
    suspicious_ext = [".locked", ".encrypted", ".enc", ".cry"]
    scan_dir = filedialog.askdirectory()
    if not scan_dir:
        threat_level_var.set("Threat Level: No Threat")
        threat_level_label.configure(foreground="green")
        return
    found = []
    for root_dir, _, files in os.walk(scan_dir):
        for file in files:
            if any(file.endswith(ext) for ext in suspicious_ext):
                full_path = os.path.join(root_dir, file)
                found.append(full_path)
    if found:
        log_message("🔍 Suspicious files found:\n" + "\n".join(found))
        for f in found:
            quarantine_file(f)
        # Update threat level based on number of files found
        count = len(found)
        if count <= 3:
            threat_level_var.set("Threat Level: Low")
            threat_level_label.configure(foreground="yellow")
        elif count <= 6:
            threat_level_var.set("Threat Level: Medium")
            threat_level_label.configure(foreground="orange")
        else:
            threat_level_var.set("Threat Level: High")
            threat_level_label.configure(foreground="red")
    else:
        log_message("✅ No ransomware signatures found.")
        threat_level_var.set("Threat Level: No Threat")
        threat_level_label.configure(foreground="green")

import webbrowser
import os

def authenticate_user():
    auth_window = tk.Toplevel()
    auth_window.title("Authentication Required")
    auth_window.geometry("300x150")
    auth_window.resizable(False, False)

    tk.Label(auth_window, text="Enter Password:", font=("Arial", 12)).pack(pady=10)
    password_entry = tk.Entry(auth_window, show="*", font=("Arial", 12))
    password_entry.pack(pady=5)

    auth_result = {"authenticated": False}

    def check_password():
        password = password_entry.get()
        # For demonstration, password is hardcoded as '123'
        if password == "123":
            auth_result["authenticated"] = True
            auth_window.destroy()
        else:
            messagebox.showerror("Authentication Failed", "Incorrect password. Try again.")

    tk.Button(auth_window, text="Submit", command=check_password).pack(pady=10)
    auth_window.grab_set()
    auth_window.wait_window()
    return auth_result["authenticated"]

def show_fake_payment_page():
    # Open the fake payment page in the default web browser
    fake_payment_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "fake_payment_site", "index.html"))
    fake_payment_url = f"file:///{fake_payment_path.replace(os.sep, '/')}"
    webbrowser.open(fake_payment_url)

    # Ask user to confirm payment completion
    result = messagebox.askyesno("Payment Confirmation", "Have you completed the payment?")

    return result

def decrypt_file_with_auth():
    if not authenticate_user():
        log_message("❌ Decryption aborted due to failed authentication.")
        return
    file_path = filedialog.askopenfilename()
    if not file_path:
        return
    # Show fake payment page before decryption
    if not show_fake_payment_page():
        log_message("❌ Decryption aborted due to unpaid fake payment.")
        messagebox.showwarning("Payment Required", "You must complete the payment to decrypt the file.")
        return
    key = load_key()
    fernet = Fernet(key)

    # Create progress window
    progress_win = tk.Toplevel()
    progress_win.title("Decrypting File")
    progress_win.geometry("400x100")
    progress_win.resizable(False, False)
    ttk.Label(progress_win, text="Decrypting file, please wait...").pack(pady=10)
    progress_bar = ttk.Progressbar(progress_win, orient="horizontal", length=300, mode="indeterminate")
    progress_bar.pack(pady=10)
    progress_bar.start()

    try:
        with open(file_path, "rb") as file:
            encrypted_data = file.read()
        decrypted_data = fernet.decrypt(encrypted_data)
        with open(file_path, "wb") as file:
            file.write(decrypted_data)
        log_message(f"🟢 File Decrypted: {file_path}")
        messagebox.showinfo("Decryption Complete", "File decryption completed successfully.")
    except Exception as e:
        log_message(f"❌ Decryption failed: {e}")
        messagebox.showerror("Decryption Error", f"Failed to decrypt file: {e}")
    finally:
        progress_bar.stop()
        progress_win.destroy()

# Update decrypt button in GUI to use decrypt_file_with_auth

# Monitor Suspicious Process Behavior
def monitor_process_behavior():
    def behavior_analyzer():
        while True:
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                if proc.info['cpu_percent'] > 80 or proc.info['memory_percent'] > 50:
                    log_message(f"⚠️ Suspicious process detected: {proc.info}")
            time.sleep(10)
    threading.Thread(target=behavior_analyzer, daemon=True).start()
    log_message("🧠 Process Behavior Monitoring started...")

# Restore From Backup
def restore_from_backup():
    backup_file = filedialog.askopenfilename(initialdir=BACKUP_FOLDER, title="Select Backup File")
    if not backup_file:
        return
    restore_path = filedialog.asksaveasfilename(title="Restore To")
    if not restore_path:
        return
    try:
        shutil.copy(backup_file, restore_path)
        log_message(f"♻️ File restored from backup to: {restore_path}")
    except Exception as e:
        log_message(f"❌ Restore failed: {e}")

# Real-Time Directory Monitor
class RansomwareEventHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if not event.is_directory:
            log_message(f"⚠️ File modified: {event.src_path}")

    def on_created(self, event):
        if not event.is_directory:
            log_message(f"📝 New file created: {event.src_path}")

    def on_deleted(self, event):
        if not event.is_directory:
            log_message(f"❌ File deleted: {event.src_path}")

def monitor_directory():
    directory = filedialog.askdirectory()
    if not directory:
        return
    event_handler = RansomwareEventHandler()
    observer = Observer()
    observer.schedule(event_handler, directory, recursive=True)
    observer.start()
    threading.Thread(target=lambda: observer.join(), daemon=True).start()
    log_message(f"🟢 Real-time directory monitoring started on: {directory}")

# GUI Setup

root = ttk.Window(themename="cyborg")
root.title("Ransomware Detection Tool")

# Set fullscreen
# root.attributes("-fullscreen", True)
root.configure(bg="#121212")

# Get screen width and height
screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()

gif_height = 200  # Height of the gif at the bottom

# Load and resize background.gif to desired width and height and animate it as full background
bg_image = Image.open("background.gif")

# Extract frames
frames = []
try:
    while True:
        frame = bg_image.copy()
        frame = frame.convert("RGBA")  # Convert to RGBA to avoid mode issues
        frame = frame.resize((screen_width, screen_height), Image.Resampling.LANCZOS)
        frames.append(ImageTk.PhotoImage(frame))
        bg_image.seek(bg_image.tell() + 1)
except EOFError:
    pass

frame_count = len(frames)
current_frame = 0

background_label = ttk.Label(root)
background_label.place(x=0, y=0, width=screen_width, height=screen_height)
background_label.lower()  # Send to back to act as background

def animate_gif():
    global current_frame
    background_label.configure(image=frames[current_frame])
    current_frame = (current_frame + 1) % frame_count
    root.after(100, animate_gif)  # Adjust delay as needed for gif speed

animate_gif()

# Header Frame
header_frame = ttk.Frame(root, padding=10)
header_frame.configure(style="TFrame")
header_frame.pack(fill="x")

header_label = ttk.Label(header_frame, text="Ransomware Detection Tool", font=("Segoe UI", 20, "bold"), foreground="#00ff00", background="#121212")
header_label.pack(anchor="center")

# Threat Level Indicator Label (added)
threat_level_var = tk.StringVar(value="Threat Level: No Threat")
threat_level_label = ttk.Label(header_frame, textvariable=threat_level_var, font=("Segoe UI", 14, "bold"), foreground="green", background="#121212")
threat_level_label.pack(anchor="center", pady=(5, 0))

# Buttons Frame
buttons_frame = ttk.Frame(root, padding=10)
buttons_frame.pack(fill="x", pady=(10, 0))

# Left Buttons Panel
left_panel = ttk.Labelframe(buttons_frame, text="Actions", padding=10)
left_panel.pack(side="left", fill="both", expand=True, padx=(0, 5))

# Right Buttons Panel
right_panel = ttk.Labelframe(buttons_frame, text="Utilities", padding=10)
right_panel.pack(side="right", fill="both", expand=True, padx=(5, 0))


# Removed gif_frame and its background_label and related GIF animation code to avoid conflict with full screen background GIF


# Left panel buttons
import time


def play_police_siren_sound():
    import time
    DURATION = 100  # milliseconds per beep
    FREQ1 = 700
    FREQ2 = 1000
    cycles = 10  # total beeps (5 cycles of alternating tones)

    def beep(freq):
        winsound.Beep(freq, DURATION)

    for _ in range(cycles):
        beep(FREQ1)
        beep(FREQ2)

import threading
import time

def play_sos_sound():
    # Play the first 3 seconds of SOS.mp3 using pygame
    def play():
        pygame.mixer.init()
        pygame.mixer.music.load("SOS.mp3")
        pygame.mixer.music.play()
        time.sleep(3)
        pygame.mixer.music.stop()
    threading.Thread(target=play, daemon=True).start()

def lock_system_with_alert():
    play_sos_sound()
    if messagebox.askyesno("Confirm Shutdown", "Are you sure you want to shutdown the system?"):
        time.sleep(1)  # Wait for 1 second to let the sound play completely
        os.system("shutdown /s /t 1")

left_buttons = [
    ("Simulate Ransomware", simulate_ransomware, "secondary"),
    ("Detect Ransomware (Honeypot)", detect_ransomware, "secondary"),
    ("Lock System (Emergency)", lock_system_with_alert, "danger"),
    ("Encrypt File", encrypt_file, "primary"),
]

for text, command, color in left_buttons:
    ttk.Button(left_panel, text=text, command=command, bootstyle=color, width=30).pack(pady=5)

# Show welcome page on app start

# Right panel buttons
# Removed threat_heatmap function and related imports as per user request

def ai_scan():
    # Load the trained AI model
    try:
        with open("ransomware_detector.pkl", "rb") as model_file:
            model = pickle.load(model_file)
        log_message(f"Loaded AI model type: {type(model)}")
    except Exception as e:
        log_message(f"❌ Failed to load AI model: {e}")
        messagebox.showerror("Error", f"Failed to load AI model: {e}")
        return

    # Define directory to scan automatically (e.g., current working directory)
    scan_dir = os.getcwd()
    log_message(f"🤖 Starting AI scan in directory: {scan_dir}")

    suspicious_files = []
    suspicious_ext = [".locked", ".encrypted", ".enc", ".cry", ".crypt"]

    import math

    def calculate_entropy(file_path):
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            if not data:
                return 0.0
            entropy = 0
            for x in range(256):
                p_x = data.count(bytes([x])) / len(data)
                if p_x > 0:
                    entropy -= p_x * math.log2(p_x)
            return entropy
        except Exception as e:
            log_message(f"❌ Error calculating entropy for {file_path}: {e}")
            return 0.0

    # Feature extraction function (updated to include file size and entropy)
    def extract_features(file_path):
        ext = os.path.splitext(file_path)[1].lower()
        ext_map = {".locked": 1, ".encrypted": 2, ".enc": 3, ".cry": 4, ".crypt": 5}
        ext_encoded = ext_map.get(ext, 0)
        try:
            file_size = os.path.getsize(file_path)
        except Exception as e:
            log_message(f"❌ Error getting file size for {file_path}: {e}")
            file_size = 0
        entropy = calculate_entropy(file_path)
        return np.array([[ext_encoded, file_size, entropy]])

    # Scan files and predict using the model
    for root_dir, _, files in os.walk(scan_dir):
        for file in files:
            full_path = os.path.join(root_dir, file)
            features = extract_features(full_path)
            try:
                prediction = model.predict(features)
                if prediction[0] == 1:  # Assuming 1 means ransomware detected
                    suspicious_files.append(full_path)
            except Exception as e:
                log_message(f"❌ Prediction error for file {full_path}: {e}")

    if suspicious_files:
        log_message("🤖 AI Scan detected suspicious files:\n" + "\n".join(suspicious_files))
        for f in suspicious_files:
            quarantine_file(f)
        count = len(suspicious_files)
        if count <= 3:
            threat_level_var.set("Threat Level: AI Scan - Low")
            threat_level_label.configure(foreground="yellow")
        elif count <= 6:
            threat_level_var.set("Threat Level: AI Scan - Medium")
            threat_level_label.configure(foreground="orange")
        else:
            threat_level_var.set("Threat Level: AI Scan - High")
            threat_level_label.configure(foreground="red")
    else:
        log_message("🤖 AI Scan found no suspicious files.")
        threat_level_var.set("Threat Level: AI Scan - No Threat")
        threat_level_label.configure(foreground="green")
    log_message("🤖 AI scan complete.")

right_buttons = [
    ("Decrypt File (Auth)", decrypt_file_with_auth, "primary"),
    ("Ransomware Signature Scan", ransomware_signature_scanner, "secondary"),
    ("AI Scan", ai_scan, "secondary"),
    ("Restore from Backup", restore_from_backup, "primary"),
    ("Generate Threat Report", generate_threat_report, "secondary"),
    # Removed "Threat Heatmap" button as per user request
]

for text, command, color in right_buttons:
    ttk.Button(right_panel, text=text, command=command, bootstyle=color, width=30).pack(pady=5)

# Log Frame
log_frame = ttk.Labelframe(root, text="Activity Log", padding=10)
log_frame.pack(side="bottom", fill="x", expand=False, padx=10, pady=5)

log_text = scrolledtext.ScrolledText(log_frame, height=8, width=85, wrap=tk.WORD, bg="#1e1e1e", fg="#00ff00", insertbackground="#00ff00", font=("Consolas", 10))
log_text.pack(fill="x", expand=False)
log_text.insert(tk.END, "Logs will appear here...\n")
log_text.configure(state='disabled')

# Exit Button Frame
exit_frame = ttk.Frame(root, padding=10)
exit_frame.pack(fill="x")

# Add Exit Button
exit_button = ttk.Button(exit_frame, text="Exit", command=root.destroy, bootstyle="danger", width=30)
exit_button.pack(pady=5)

# Define pressed style for button animation with 3D effect
style = ttk.Style()
style.configure("Pressed.TButton", background="#00ff00", foreground="#000000", relief="sunken", borderwidth=4)

def animate_button(event):
    btn = event.widget
    original_style = btn.cget("style")

    def press():
        btn.configure(style="Pressed.TButton")

    def restore():
        btn.configure(style=original_style)

    press()
    btn.after(200, restore)

# Bind animation to all buttons in left_panel and right_panel
for child in left_panel.winfo_children():
    if isinstance(child, ttk.Button):
        child.bind("<Button-1>", animate_button)

for child in right_panel.winfo_children():
    if isinstance(child, ttk.Button):
        child.bind("<Button-1>", animate_button)

# The exit_button variable is not defined, define it here to bind the animation

exit_button = None
for child in exit_frame.winfo_children():
    if isinstance(child, ttk.Button) and child.cget("text") == "Exit":
        exit_button = child
        break

if exit_button:
    exit_button.bind("<Button-1>", animate_button)

def toggle_usb_monitoring():
    global usb_monitoring
    if usb_monitoring:
        monitor_usb_devices(start=False)
        usb_monitor_btn.config(text="Start USB Monitoring")
    else:
        monitor_usb_devices(start=True)
        usb_monitor_btn.config(text="Stop USB Monitoring")

usb_monitor_btn = ttk.Button(left_panel, text="Start USB Monitoring", command=toggle_usb_monitoring, bootstyle="info", width=30)
usb_monitor_btn.pack(pady=5)

root.mainloop()
