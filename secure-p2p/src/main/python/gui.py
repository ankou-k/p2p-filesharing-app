import sys
import os
import logging
import argparse
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                             QListWidget, QPushButton, QTableWidget, QTableWidgetItem, 
                             QLineEdit, QLabel, QMessageBox, QInputDialog, QFileDialog)
from PyQt5.QtCore import QThread, Qt, QTimer
from secure_p2p_client import SecureP2PFileSharing, P2PFileShareThread
import hashlib
import tempfile

class SecureP2PFileShareGUI(QMainWindow):
    def __init__(self, username: str = None, port: int = 0):
        super().__init__()
        self.username = username or f"User_{os.getpid()}"
        self.p2p_client = SecureP2PFileSharing(self.username, port)
        self.logger = logging.getLogger(f"GUI-{self.username}")
        self.init_ui()
        
        self.thread = QThread()
        self.worker = P2PFileShareThread(self.p2p_client)
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.setup_signals()
        self.thread.start()

    def init_ui(self):
        self.setWindowTitle(f"Secure P2P File Sharing - {self.username}")
        self.setGeometry(100, 100, 800, 600)

        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QHBoxLayout(main_widget)

        left_panel = QVBoxLayout()
        self.peers_list = QListWidget()
        self.peers_list.itemClicked.connect(self.peer_selected)
        left_panel.addWidget(QLabel("Discovered Peers"))
        left_panel.addWidget(self.peers_list)
        

        self.contacts_list = QTableWidget(0, 3)
        self.contacts_list.setHorizontalHeaderLabels(["Name", "Fingerprint", "Action"])
        left_panel.addWidget(QLabel("Verified Contacts"))
        left_panel.addWidget(self.contacts_list)

        right_panel = QVBoxLayout()
        self.shared_files_list = QTableWidget(0, 3)
        self.shared_files_list.setHorizontalHeaderLabels(["Name", "Size", "Hash"])
        right_panel.addWidget(QLabel("Shared Files"))
        right_panel.addWidget(self.shared_files_list)

        share_file_btn = QPushButton("Share New File")
        share_file_btn.clicked.connect(self.share_file)
        right_panel.addWidget(share_file_btn)

        send_file_btn = QPushButton("Send File")
        send_file_btn.clicked.connect(self.send_file_dialog)
        right_panel.addWidget(send_file_btn)

        self.received_files_list = QTableWidget(0, 4)
        self.received_files_list.setHorizontalHeaderLabels(["Name", "Size", "Hash", "Action"])
        right_panel.addWidget(QLabel("Received Files"))
        right_panel.addWidget(self.received_files_list)

        refresh_received_btn = QPushButton("Show Received Files")
        refresh_received_btn.clicked.connect(self.refresh_received_files)
        right_panel.addWidget(refresh_received_btn)

        button_layout = QHBoxLayout()
        self.connect_btn = QPushButton("Connect to Peer")
        self.connect_btn.clicked.connect(self.connect_to_peer)
        button_layout.addWidget(self.connect_btn)

        self.view_files_btn = QPushButton("View Peer Files")
        self.view_files_btn.clicked.connect(self.view_peer_files)
        button_layout.addWidget(self.view_files_btn)

        self.add_contact_btn = QPushButton("Add Contact")
        self.add_contact_btn.clicked.connect(self.add_contact_dialog)
        button_layout.addWidget(self.add_contact_btn)

        rotate_keys_btn = QPushButton("Rotate Keys")
        rotate_keys_btn.clicked.connect(self.rotate_keys_dialog)
        button_layout.addWidget(rotate_keys_btn)

        right_panel.addLayout(button_layout)
        layout.addLayout(left_panel)
        layout.addLayout(right_panel)
        
        self.refresh_shared_files_list()

    def setup_signals(self):
        self.p2p_client.notify_connection_request = lambda request: self.worker.connection_requested.emit(request)
        self.p2p_client.notify_connection_status_changed = lambda peer_id, connected: self.worker.connection_status_changed.emit(peer_id, connected)
        self.p2p_client.notify_file_transfer_status = lambda f, p, s, e="": self.worker.file_transfer_status.emit(f, p, s, e)
        self.worker.peers_discovered.connect(self.update_peers_list)
        self.worker.connection_requested.connect(self.handle_connection_request)
        self.worker.connection_status_changed.connect(self.handle_connection_status_changed)
        self.worker.file_transfer_status.connect(self.handle_file_transfer_status)


    def update_peers_list(self, peers):
        self.peers_list.clear()
        for peer in peers:
            self.peers_list.addItem(peer)

    def handle_connection_request(self, request):
        peer_id = request['peer_id']
        peer_name = request['peer_name']
        fingerprint = request.get('fingerprint', 'Unknown')
        reply = QMessageBox.question(self, "Connection Request",
                                     f"{peer_name} ({peer_id}) wants to connect.\nFingerprint: {fingerprint}\nAccept?",
                                     QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes:
            self.p2p_client.accept_connection(peer_id)

    def handle_connection_status_changed(self, peer_id, connected):
        self.logger.info(f"Connection status changed: peer_id={peer_id}, connected={connected}")
        self.update_peers_list([f"{peer.get('username', 'Unknown')} {'(Connected)' if peer.get('connected', False) else '(Discovered)'}"
                                for peer in self.p2p_client.get_discovered_peers()])

    def handle_file_transfer_status(self, file_name, progress, status, error_msg=""):
        if status == "completed":
            QMessageBox.information(self, "File Transfer", f"File {file_name} transfer completed!")
            self.refresh_shared_files_list()
            self.refresh_received_files() 
            if hasattr(self, 'selected_peer'):
                self.view_peer_files()
        elif status == "failed":
            message = f"File {file_name} transfer failed!"
            if error_msg:
                message += f"\nError: {error_msg}"
            QMessageBox.warning(self, "File Transfer", message)

    def peer_selected(self, item):
        self.selected_peer = item.text().split()[0]

    def connect_to_peer(self):
        if hasattr(self, 'selected_peer'):
            peer_id = next((p['id'] for p in self.p2p_client.known_peers.values() if p['username'] == self.selected_peer), None)
            if peer_id and self.p2p_client.request_connection(peer_id):
                QMessageBox.information(self, "Connection", f"Connection request sent to {self.selected_peer}")
            else:
                QMessageBox.warning(self, "Error", "Failed to send connection request")

    def view_peer_files(self):
        if hasattr(self, 'selected_peer'):
            peer_id = next((p['id'] for p in self.p2p_client.known_peers.values() if p['username'] == self.selected_peer), None)
            if peer_id:
                files = self.p2p_client.get_files_from_peer(peer_id)
                self.received_files_list.setRowCount(0)
                for i, file in enumerate(files):
                    self.received_files_list.insertRow(i)
                    self.received_files_list.setItem(i, 0, QTableWidgetItem(file['name']))
                    self.received_files_list.setItem(i, 1, QTableWidgetItem(str(file['size'])))
                    self.received_files_list.setItem(i, 2, QTableWidgetItem(file['hash']))
                    download_btn = QPushButton("Download")
                    download_btn.clicked.connect(lambda checked, f=file, p=peer_id: self.download_file(f, p))
                    self.received_files_list.setCellWidget(i, 3, download_btn)

    def add_contact_dialog(self):
        name, ok1 = QInputDialog.getText(self, "Add Contact", "Enter peer name:")
        if ok1:
            fingerprint, ok2 = QInputDialog.getText(self, "Add Contact", "Enter peer fingerprint:")
            if ok2:
                self.p2p_client.add_verified_peer(name, fingerprint)
                self.refresh_contacts_list()

    def view_decrypted_file(self, file_name):
        try:
            # Get the file path
            file_path = os.path.join(self.p2p_client.received_files_dir, file_name)
            
            # Generate the local key
            local_key = hashlib.sha256(self.p2p_client.auth_manager.generate_fingerprint().encode()).digest()
            
            # Decrypt the file
            decrypted_data = self.p2p_client._decrypt_file(file_path, local_key)
            
            # Create a temporary file with the decrypted content
            temp_dir = tempfile.gettempdir()
            temp_path = os.path.join(temp_dir, file_name)
            
            with open(temp_path, 'wb') as f:
                f.write(decrypted_data)
            
            # Open the file with default application
            if sys.platform == 'win32':
                os.startfile(temp_path)
            else:
                subprocess.call(('xdg-open', temp_path))
                
            QTimer.singleShot(60000, lambda: os.unlink(temp_path) if os.path.exists(temp_path) else None)
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Could not decrypt file: {str(e)}")

    def refresh_received_files(self):
        """Display files that have been downloaded locally"""
        self.received_files_list.setRowCount(0)
        
        if not os.path.exists(self.p2p_client.received_files_dir):
            return
        
        files = []
        for filename in os.listdir(self.p2p_client.received_files_dir):
            file_path = os.path.join(self.p2p_client.received_files_dir, filename)
            if os.path.isfile(file_path):
                file_size = os.path.getsize(file_path)
                files.append({
                    'name': filename,
                    'size': file_size,
                    'path': file_path
                })
        
        for i, file in enumerate(files):
            self.received_files_list.insertRow(i)
            self.received_files_list.setItem(i, 0, QTableWidgetItem(file['name']))
            self.received_files_list.setItem(i, 1, QTableWidgetItem(str(file['size'])))
            self.received_files_list.setItem(i, 2, QTableWidgetItem("Local"))
            
            view_btn = QPushButton("View Decrypted")
            view_btn.clicked.connect(lambda checked, f=file['name']: self.view_decrypted_file(f))
            self.received_files_list.setCellWidget(i, 3, view_btn)


    def refresh_contacts_list(self):
        self.contacts_list.setRowCount(0)
        for peer_id, peer_info in self.p2p_client.auth_manager.verified_peers.items():
            row = self.contacts_list.rowCount()
            self.contacts_list.insertRow(row)
            peer_name = self.p2p_client.known_peers.get(peer_id, {}).get('username', 'Unknown')
            self.contacts_list.setItem(row, 0, QTableWidgetItem(peer_name))
            self.contacts_list.setItem(row, 1, QTableWidgetItem(peer_info['fingerprint']))

    def share_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Share")
        if file_path:
            try:
                result = self.p2p_client.add_shared_file(file_path)
                if result:
                    self.refresh_shared_files_list()
                    QMessageBox.information(self, "File Shared", f"File {os.path.basename(file_path)} is now shared")
                else:
                    QMessageBox.warning(self, "Error", "Failed to share file")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Error sharing file: {str(e)}")

    def send_file_dialog(self):
        if hasattr(self, 'selected_peer'):
            peer_id = next((p['id'] for p in self.p2p_client.known_peers.values() if p['username'] == self.selected_peer), None)
            if peer_id:
                file_name, _ = QFileDialog.getOpenFileName(self, "Select File to Send")
                if file_name and self.p2p_client.send_file(peer_id, os.path.basename(file_name)):
                    QMessageBox.information(self, "File Sent", f"File {file_name} sent successfully")
                else:
                    QMessageBox.warning(self, "Error", "Failed to send file")

    def refresh_shared_files_list(self):
        files = self.p2p_client.list_shared_files()
        self.shared_files_list.setRowCount(0)
        for i, file in enumerate(files):
            self.shared_files_list.insertRow(i)
            self.shared_files_list.setItem(i, 0, QTableWidgetItem(file['name']))
            self.shared_files_list.setItem(i, 1, QTableWidgetItem(str(file['size'])))
            self.shared_files_list.setItem(i, 2, QTableWidgetItem(file['hash']))

    def download_file(self, file_info, peer_id):
        if not file_info or not peer_id:
            QMessageBox.warning(self, "Error", "Invalid file or peer information")
            return
        reply = QMessageBox.question(self, "Download File", 
                                     f"Download {file_info['name']} from {self.selected_peer}?",
                                     QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes:
            success = self.p2p_client.request_file_download(peer_id, file_info['name'], file_info['hash'])
            if success:
                QMessageBox.information(self, "Download Started", f"Download of {file_info['name']} has started")
            else:
                QMessageBox.warning(self, "Download Failed", f"Failed to start download of {file_info['name']}")

    def rotate_keys_dialog(self):
        password, ok = QInputDialog.getText(self, "Rotate Keys", "Enter master password:")
        if ok:
            success, fingerprint = self.p2p_client.auth_manager.rotate_keys(password)
            if success:
                self.p2p_client.notify_key_change()
                QMessageBox.information(self, "Keys Rotated", f"New fingerprint: {fingerprint}")
            else:
                QMessageBox.warning(self, "Error", "Key rotation failed")

    def closeEvent(self, event):
        self.p2p_client.close()
        self.worker.stop()
        self.thread.quit()
        self.thread.wait()
        event.accept()

def main():
    parser = argparse.ArgumentParser(description='Secure P2P File Sharing')
    parser.add_argument('--username', default=None, help='Username for this instance')
    parser.add_argument('--port', type=int, default=0, help='Port to use (0 for auto-assigned)')
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    
    app = QApplication(sys.argv)
    gui = SecureP2PFileShareGUI(username=args.username, port=args.port)
    gui.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()