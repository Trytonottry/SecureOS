# Secure OS Core with advanced security and usability features
import os
import shutil
import hashlib
import subprocess
from cryptography.fernet import Fernet
import docker
import logging
from smtplib import SMTP
import tkinter as tk
from tkinter import messagebox, filedialog

class SecureOS:
    def __init__(self):
        self.key = Fernet.generate_key()
        self.cipher_suite = Fernet(self.key)
        self.supported_extensions = [".txt", ".sh", ".so", ".py"]
        self.preinstalled_apps = ["metasploit", "john", "hashcat", "nmap", "wireshark", "snort", "suricata"]
        self.logs = []  # Logs for security monitoring
        self.setup_docker()
        self.setup_logging()
        self.setup_firewall()
        self.alert_recipients = ["admin@example.com"]  # Email for critical alerts

    def setup_logging(self):
        """Set up centralized logging."""
        logging.basicConfig(filename="secure_os.log", level=logging.INFO,
                            format="%(asctime)s - %(levelname)s - %(message)s")
        logging.info("Logging system initialized.")

    def send_alert(self, message):
        """Send email alert for critical events."""
        try:
            with SMTP("smtp.example.com") as smtp:
                smtp.login("alert@example.com", "password")
                for recipient in self.alert_recipients:
                    smtp.sendmail("alert@example.com", recipient, f"Subject: Critical Alert\n\n{message}")
            logging.info("Alert sent to administrators.")
        except Exception as e:
            logging.error(f"Failed to send alert: {e}")

    def encrypt_data(self, data):
        """Encrypt sensitive data."""
        return self.cipher_suite.encrypt(data.encode())

    def decrypt_data(self, encrypted_data):
        """Decrypt sensitive data."""
        return self.cipher_suite.decrypt(encrypted_data).decode()

    def monitor_activity(self, action):
        """Log user activity for monitoring."""
        self.logs.append(action)
        if len(self.logs) > 100:  # Limit log size
            self.logs.pop(0)
        logging.info(f"Activity logged: {action}")

    def rewrite_on_intrusion(self):
        """Rewrite key system files in case of intrusion."""
        try:
            backup_dir = "./system_backup"
            if os.path.exists(backup_dir):
                for root, dirs, files in os.walk(backup_dir):
                    for file in files:
                        shutil.copy(os.path.join(root, file), root.replace("system_backup", "system"))
            self.send_alert("System integrity restored after intrusion detected.")
        except Exception as e:
            logging.error(f"Error during rewrite: {e}")

    def detect_intrusion(self):
        """Simple intrusion detection mechanism."""
        critical_files = ["./system/kernel", "./system/config"]
        for file in critical_files:
            if not os.path.exists(file) or os.path.getsize(file) == 0:
                logging.warning("Intrusion detected! Rewriting system files.")
                self.rewrite_on_intrusion()
                break

    def install_preinstalled_apps(self):
        """Install preconfigured security applications."""
        for app in self.preinstalled_apps:
            try:
                logging.info(f"Installing {app}...")
                subprocess.run(["apt-get", "install", "-y", app], check=True)
            except Exception as e:
                logging.error(f"Failed to install {app}: {e}")

    def handle_file(self, filename):
        """Handle file based on its extension."""
        _, ext = os.path.splitext(filename)
        if ext in self.supported_extensions:
            logging.info(f"Handling {ext} file: {filename}")
            self.run_in_sandbox(filename)
        else:
            logging.warning(f"Unsupported file type: {ext}")

    def run_in_sandbox(self, filename):
        """Run file inside a Docker container to isolate its execution."""
        try:
            client = docker.from_env()
            logging.info(f"Running {filename} in sandbox...")
            container = client.containers.run(
                image="debian", command=f"bash {filename}", detach=True, auto_remove=True
            )
            for line in container.logs(stream=True):
                logging.info(line.strip().decode())
        except Exception as e:
            logging.error(f"Sandbox error: {e}")

    def setup_docker(self):
        """Ensure Docker is installed and running."""
        try:
            subprocess.run(["systemctl", "start", "docker"], check=True)
            logging.info("Docker is running.")
        except Exception as e:
            logging.error(f"Error starting Docker: {e}")

    def setup_firewall(self):
        """Set up basic firewall rules."""
        try:
            subprocess.run(["ufw", "default", "deny"], check=True)
            subprocess.run(["ufw", "allow", "22"], check=True)  # Allow SSH
            subprocess.run(["ufw", "enable"], check=True)
            logging.info("Firewall configured.")
        except Exception as e:
            logging.error(f"Firewall setup error: {e}")

    def setup_disk_encryption(self):
        """Encrypt disk using LUKS."""
        logging.info("Configuring full disk encryption...")
        print("Ensure to use LUKS during system installation.")

    def setup_integrity_check(self):
        """Install and configure AIDE for system integrity checks."""
        try:
            subprocess.run(["apt-get", "install", "-y", "aide"], check=True)
            subprocess.run(["aideinit"], check=True)
            shutil.move("/var/lib/aide/aide.db.new", "/var/lib/aide/aide.db")
            logging.info("AIDE configured for integrity checks.")
        except Exception as e:
            logging.error(f"Failed to configure AIDE: {e}")

    def launch_gui(self):
        """Launch the graphical user interface."""
        def encrypt_action():
            data = encrypt_entry.get()
            if data:
                encrypted = self.encrypt_data(data)
                messagebox.showinfo("Encryption Result", f"Encrypted: {encrypted}")

        def decrypt_action():
            data = encrypt_entry.get()
            if data:
                try:
                    decrypted = self.decrypt_data(data.encode())
                    messagebox.showinfo("Decryption Result", f"Decrypted: {decrypted}")
                except Exception as e:
                    messagebox.showerror("Error", f"Decryption failed: {e}")

        def handle_file_action():
            filepath = filedialog.askopenfilename()
            if filepath:
                self.handle_file(filepath)
                messagebox.showinfo("File Handling", f"Handled file: {filepath}")

        root = tk.Tk()
        root.title("Secure OS GUI")

        tk.Label(root, text="Enter text to encrypt/decrypt:").pack(pady=5)
        encrypt_entry = tk.Entry(root, width=50)
        encrypt_entry.pack(pady=5)

        tk.Button(root, text="Encrypt", command=encrypt_action).pack(pady=5)
        tk.Button(root, text="Decrypt", command=decrypt_action).pack(pady=5)
        tk.Button(root, text="Handle File", command=handle_file_action).pack(pady=5)

        tk.Button(root, text="Exit", command=root.quit).pack(pady=10)

        root.mainloop()

    def run(self):
        """Main system loop."""
        self.install_preinstalled_apps()
        self.setup_integrity_check()
        print("Secure OS is now running with GUI.")
        self.launch_gui()

if __name__ == "__main__":
    os_system = SecureOS()
    os_system.run()
