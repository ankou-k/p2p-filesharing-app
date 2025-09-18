import os
import json
import uuid
import socket
import threading
import time
import logging
import shutil
import hashlib
import base64
from typing import Dict, List, Optional, Tuple
from zeroconf import Zeroconf, ServiceInfo
from PyQt5.QtCore import QObject, pyqtSignal
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from auth_manager import AuthenticationManager

class P2PFileShareThread(QObject):
    peers_discovered = pyqtSignal(list)
    connection_requested = pyqtSignal(dict)
    connection_status_changed = pyqtSignal(str, bool)
    file_transfer_status = pyqtSignal(str, int, str, str)

    def __init__(self, client):
        super().__init__()
        self.client = client
        self.running = True

    def run(self):
        while self.running:
            peers = self.client.get_discovered_peers()
            formatted_peers = [f"{peer.get('username', 'Unknown')} {'(Connected)' if peer.get('connected', False) else '(Discovered)'}" for peer in peers]
            self.peers_discovered.emit(formatted_peers)
            time.sleep(2)

    def stop(self):
        self.running = False

class SecureP2PFileSharing:
    def __init__(self, username: str, port: int = 0, data_dir: Optional[str] = None):
        self.username = username
        self.user_id = str(uuid.uuid4())
        self.data_dir = data_dir or os.path.join(os.getcwd(), "p2p_data")
        os.makedirs(self.data_dir, exist_ok=True)
        self.auth_manager = AuthenticationManager(self.username, self.data_dir)
        self.logger = logging.getLogger(f"P2P-{username}")
        
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind(('', port or 0))
        self.comm_port = self.server_socket.getsockname()[1]
        self.server_socket.listen(5)
        
        self.known_peers: Dict[str, Dict] = {}
        self.connected_peers: Dict[str, Dict] = {}
        self.pending_requests: List[Dict] = []
        self.shared_files: List[Dict] = []
        self.received_files: List[Dict] = []
        self.received_files_dir = os.path.join(self.data_dir, "received")
        self.shared_files_dir = os.path.join(self.data_dir, "shared")
        os.makedirs(self.received_files_dir, exist_ok=True)
        os.makedirs(self.shared_files_dir, exist_ok=True)
        
        self.running = True
        self._is_requesting_files = False
        self.zconf = Zeroconf()
        self._start_comm_thread()
        self.start_mdns_discovery()

    def _start_comm_thread(self):
        comm_thread = threading.Thread(target=self._communication_loop, daemon=True)
        comm_thread.start()
        self.logger.debug("Started communication thread")

    def _communication_loop(self):
        while self.running:
            try:
                client_socket, addr = self.server_socket.accept()
                message_data = client_socket.recv(4096).decode('utf-8').strip()
                if message_data:
                    messages = message_data.split('\n')
                    for message_str in messages:
                        if message_str.strip():
                            try:
                                message = json.loads(message_str)
                                self._handle_message(message, addr, client_socket)
                            except json.JSONDecodeError as e:
                                self.logger.error(f"Invalid message from {addr}: {e}")
            except Exception as e:
                if self.running:
                    self.logger.error(f"Comm loop error: {e}")
            finally:
                client_socket.close()

    def _handle_message(self, message: Dict, addr: Tuple[str, int], client_socket: socket.socket):
        msg_type = message.get('type')
        if msg_type == 'connection_request':
            self._handle_connection_request(message, addr)
        elif msg_type == 'connection_response':
            self._handle_connection_response(message)
        elif msg_type == 'list_files_request':
            self._handle_list_files_request(message, client_socket)
        elif msg_type == 'file_download_request':
            sender_id = message.get('sender_id')
            file_name = message.get('file_name')
            if sender_id not in self.auth_manager.verified_peers:
                self.logger.warning(f"Unauthorized file download attempt from unverified peer: {sender_id}")
                response = {
                    'type': 'file_download_response',
                    'status': 'denied',
                    'reason': 'Not authorized - peer not verified',
                    'file_name': file_name
                }
                client_socket.sendall(json.dumps(response).encode('utf-8') + b'\n')
                return
        
            if sender_id in self.connected_peers:
                consent = self._request_file_consent(sender_id, file_name)
                private_key = ec.generate_private_key(ec.SECP384R1())
                public_key = private_key.public_key()
                peer_public = serialization.load_der_public_key(
                    base64.b64decode(message['ephemeral_public']),
                    backend=default_backend()
                )
                shared_key = private_key.exchange(ec.ECDH(), peer_public)
                key = hashlib.sha256(shared_key).digest()
                response = {
                    'type': 'file_download_response',
                    'status': 'approved' if consent else 'denied',
                    'file_name': file_name,
                    'file_size': os.path.getsize(os.path.join(self.shared_files_dir, file_name)) if consent else 0,
                    'file_hash': self._get_file_hash(file_name) if consent else '',
                    'ephemeral_public': base64.b64encode(
                        public_key.public_bytes(
                            encoding=serialization.Encoding.DER,
                            format=serialization.PublicFormat.SubjectPublicKeyInfo
                        )
                    ).decode('utf-8')
                }
                client_socket.sendall(json.dumps(response).encode('utf-8') + b'\n')
                if consent:
                    self._send_file(client_socket, file_name, key)
            client_socket.close()
        elif msg_type == 'key_change_notification':
            sender_id = message.get('sender_id')
            sender_name = message.get('sender_name', 'Unknown')
            new_fingerprint = message.get('new_fingerprint')
            self.logger.info(f"Received key change notification from {sender_name} ({sender_id}): {new_fingerprint}")
            if sender_id in self.connected_peers:
                self.auth_manager.verify_peer(sender_id, new_fingerprint)
                self.notify_connection_status_changed(sender_id, True)
                self.logger.info(f"Updated fingerprint for {sender_id}")
            else:
                self.logger.warning(f"Ignored key change from {sender_id}: not a connected peer")

    def _handle_connection_request(self, message, addr):
        sender_id = message.get('sender_id')
        sender_name = message.get('sender_name', 'Unknown')
        sender_host = addr[0]
        sender_port = message.get('sender_port', self.comm_port)
        sender_fingerprint = message.get('fingerprint', '')
        requires_mutual = message.get('requires_mutual', False)

        if sender_id not in self.known_peers:
            self.known_peers[sender_id] = {
                'username': sender_name, 'host': sender_host, 'port': sender_port,
                'id': sender_id, 'connected': False, 'fingerprint': sender_fingerprint
            }
            self.logger.info(f"Added new peer: {sender_name} ({sender_id})")
        
        request = {
            'peer_id': sender_id, 'peer_name': sender_name, 'host': sender_host,
            'port': sender_port, 'timestamp': time.time(), 'fingerprint': sender_fingerprint
        }
        self.pending_requests.append(request)
        self.logger.info(f"Received connection request from {sender_name} ({sender_id})")
        self.notify_connection_request(request)

    def _handle_connection_response(self, message):
        sender_id = message.get('sender_id') 
        accepted = message.get('accepted', False)
        sender_fingerprint = message.get('fingerprint', '')
        if sender_id in self.known_peers and accepted:
            if self.auth_manager.verify_peer(sender_id, sender_fingerprint):
                self.connected_peers[sender_id] = self.known_peers[sender_id]
                self.connected_peers[sender_id]['connected'] = True
                self.notify_connection_status_changed(sender_id, True)
                self.logger.info(f"Connection accepted by {sender_id} with verified fingerprint")
            else:
                self.logger.error(f"Fingerprint verification failed for {sender_id}")
        elif not accepted:
            self.logger.info(f"Connection rejected by {sender_id}")

    def _handle_list_files_request(self, message, client_socket):
        sender_id = message.get('user_id')
        request_id = message.get('request_id', 'unknown')
        
        # First verify that the peer is authorized
        if sender_id not in self.auth_manager.verified_peers:
            self.logger.warning(f"Unauthorized file listing attempt from unverified peer: {sender_id}")
            response = {
                'type': 'list_files_response',
                'files': [],
                'request_id': request_id,
                'error': 'Unauthorized - peer not verified'
            }
            client_socket.sendall(json.dumps(response).encode('utf-8') + b'\n')
            client_socket.shutdown(socket.SHUT_WR)
            return
        
        # Skip self-requests when already requesting files
        if self._is_requesting_files and sender_id == self.user_id:
            return
            
        # Only return file list to verified peers
        file_list = self.list_shared_files()
        response = {
            'type': 'list_files_response',
            'files': file_list,
            'request_id': request_id
        }
        client_socket.sendall(json.dumps(response).encode('utf-8') + b'\n')
        client_socket.shutdown(socket.SHUT_WR)

    def start_mdns_discovery(self):
    # Get local IP address
        def get_local_ip():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                # Try to connect to a public IP
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
                s.close()
                return local_ip
            except Exception:
                # Fallback method
                hostname = socket.gethostname()
                return socket.gethostbyname(hostname)
    
        # Get the local IP address
        local_ip = get_local_ip()
        self.logger.info(f"Using local IP address: {local_ip}")
        
        # Convert IP to the format zeroconf expects
        ip_bytes = socket.inet_aton(local_ip)
        
        service_type = "_securep2p._tcp.local."
        service_name = f"{self.user_id[:8]}-{self.username}._securep2p._tcp.local."
        info = ServiceInfo(
            service_type, service_name,
            addresses=[ip_bytes],  
            port=self.comm_port,
            properties={'user_id': self.user_id, 'username': self.username, 'pid': str(os.getpid())},
            server=f"{socket.gethostname()}.local."
        )
        self.zconf.register_service(info)
        listener = P2PServiceListener(self)
        self.zconf.add_service_listener(service_type, listener)


    def get_discovered_peers(self) -> List[Dict]:
        return list(self.known_peers.values())

    def add_shared_file(self, file_path: str) -> bool:
        if not os.path.exists(file_path):
            return False
        try:
            file_name = os.path.basename(file_path)
            dest_path = os.path.join(self.shared_files_dir, file_name)
            shutil.copy2(file_path, dest_path)
            key = hashlib.sha256(self.auth_manager.generate_fingerprint().encode()).digest()
            self._encrypt_file(dest_path, key)
            with open(dest_path, 'rb') as f:
                file_hash = hashlib.sha256(self._decrypt_file(dest_path, key)).hexdigest()
            self.shared_files.append({
                'name': file_name, 'size': os.path.getsize(dest_path), 'hash': file_hash,
                'origin': self.user_id
            })
            self.logger.info(f"Added shared file: {file_name}")
            return True
        except Exception as e:
            self.logger.error(f"Error adding shared file: {e}")
            return False

    def list_shared_files(self) -> List[Dict]:
        shared_dir = os.path.join(self.data_dir, "shared")
        os.makedirs(shared_dir, exist_ok=True)
        files = []
        key = hashlib.sha256(self.auth_manager.generate_fingerprint().encode()).digest()
        for filename in os.listdir(shared_dir):
            file_path = os.path.join(shared_dir, filename)
            if os.path.isfile(file_path):
                try:
                    decrypted_data = self._decrypt_file(file_path, key)
                    file_hash = hashlib.sha256(decrypted_data).hexdigest()
                    files.append({
                        'hash': file_hash, 'name': filename, 'size': os.path.getsize(file_path),
                        'origin': self.user_id
                    })
                except ValueError as e:
                    self.logger.error(f"Failed to decrypt {filename}: {e}")
                    continue
        return files

    def get_files_from_peer(self, peer_id: str, file_hash: str = None) -> List[Dict]:
        if file_hash:
            for pid, peer in self.connected_peers.items():
                files = self._request_file_list(peer['host'], peer['port'])
                for file in files:
                    if file['hash'] == file_hash:
                        self.request_file_download(pid, file['name'], file_hash)
                        return [file]
            return []
        if peer_id not in self.connected_peers and peer_id not in self.known_peers:
            return []
        peer = self.connected_peers.get(peer_id) or self.known_peers.get(peer_id)
        return self._request_file_list(peer['host'], peer['port'])

    def _request_file_list(self, host: str, port: int) -> List[Dict]:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(15)
                s.connect((host, port))
                request = {'type': 'list_files_request', 'user_id': self.user_id, 'request_id': str(uuid.uuid4())}
                s.sendall(json.dumps(request).encode('utf-8') + b'\n')
                response = json.loads(s.recv(4096).decode('utf-8').strip())
                return response.get('files', []) if response.get('type') == 'list_files_response' else []
        except Exception:
            return []

    def request_file_download(self, peer_id: str, file_name: str, file_hash: str = None) -> bool:
        if peer_id not in self.connected_peers and peer_id not in self.known_peers:
            return False
        peer = self.connected_peers.get(peer_id) or self.known_peers.get(peer_id)
        download_thread = threading.Thread(
            target=self._download_file,
            args=(peer['host'], peer['port'], peer_id, file_name, file_hash),
            daemon=True
        )
        download_thread.start()
        return True

    def _download_file(self, host: str, port: int, peer_id: str, file_name: str, file_hash: str = None):
        try:
            self.notify_file_transfer_status(file_name, 0, "started")
            self.logger.info(f"Starting download of {file_name} from {peer_id} at {host}:{port}")
            
            key = None  
            iv = None
            encrypted_data = b''
            bytes_received = 0
            total_encrypted_size = 0
            received_hash = ""
            dest_path = os.path.join(self.received_files_dir, file_name)
            temp_path = dest_path + '.part'
            
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(60)  
                self.logger.debug(f"Connecting to {host}:{port}")
                s.connect((host, port))
                private_key = ec.generate_private_key(ec.SECP384R1())
                public_key = private_key.public_key()
                request = {
                    'type': 'file_download_request',
                    'sender_id': self.user_id,
                    'file_name': file_name,
                    'file_hash': file_hash,
                    'ephemeral_public': base64.b64encode(
                        public_key.public_bytes(
                            encoding=serialization.Encoding.DER,
                            format=serialization.PublicFormat.SubjectPublicKeyInfo
                        )
                    ).decode('utf-8')
                }
                self.logger.debug(f"Sending download request for {file_name}")
                s.sendall(json.dumps(request).encode('utf-8') + b'\n')
                
               
                response_data = s.recv(4096)
                self.logger.debug(f"Raw response received: {response_data!r}")
                
                if not response_data:
                    self.logger.error("Received empty response from peer")
                    self.notify_file_transfer_status(file_name, 0, "failed", "Received empty response from peer")
                    return False
                
                # Try to decode the response as UTF-8 and parse as JSON
                try:
                    response_text = response_data.decode('utf-8').strip()
                    self.logger.debug(f"Decoded response: {response_text}")
                    
                    # Check if response contains valid JSON by looking for JSON indicators
                    if not (response_text.startswith('{') and response_text.endswith('}')):
                        # This might be the start of a binary file transfer instead of a JSON response
                        self.logger.warning("Response doesn't appear to be JSON, checking if it's a direct file transfer")
                        
                        if len(response_data) >= 16: 
                            self.logger.info("Attempting to process as direct file transfer")
                            
                            
                            iv = response_data[:16]
                            encrypted_data = response_data[16:]
                            
                        
                            peer_info = self.connected_peers.get(peer_id) or self.known_peers.get(peer_id, {})
                            fingerprint = peer_info.get('fingerprint', '')
                            if fingerprint:
                                # Use peer fingerprint if available as part of key derivation
                                key = hashlib.sha256(fingerprint.encode()).digest()
                            else:
                                # Fallback key as last resort - this should be improved
                                key = hashlib.sha256(f"{self.user_id}:{peer_id}".encode()).digest()
                            
                            # Set default expected values
                            file_size = -1  # Unknown size
                            received_hash = ""
                            
                            self.logger.debug("Moving to direct file processing with fallback key")
                        else:
                            self.logger.error(f"Invalid response format: response too short")
                            self.notify_file_transfer_status(file_name, 0, "failed", f"Invalid response format from peer")
                            return False
                    else:
                        # Process as normal JSON response
                        response = json.loads(response_text)
                        
                        if response.get('status') != 'approved':
                            reason = response.get('reason', 'unknown')
                            self.logger.error(f"Download rejected: {reason}")
                            self.notify_file_transfer_status(file_name, 0, "failed", f"Download rejected: {reason}")
                            return False
                        
                        self.logger.debug("Download approved, processing response...")
                        # Process the public key in DER format directly from base64
                        try:
                            peer_public = serialization.load_der_public_key(
                                base64.b64decode(response['ephemeral_public']),
                                backend=default_backend()
                            )
                            shared_key = private_key.exchange(ec.ECDH(), peer_public)
                            key = hashlib.sha256(shared_key).digest()
                            file_size = response.get('file_size', 0)
                            received_hash = response.get('file_hash', '')
                            
                            self.logger.debug(f"Expected file size: {file_size} bytes")
                            self.logger.debug(f"Expected hash: {received_hash or file_hash or 'not provided'}")
                            
                            # Receive IV (16 bytes) and encrypted data
                            self.logger.debug("Receiving IV...")
                            iv = s.recv(16)  # First 16 bytes are the IV
                        except Exception as e:
                            self.logger.error(f"Error processing key exchange: {e}")
                            # Set fallback key if key exchange fails
                            key = hashlib.sha256(f"{self.user_id}:{peer_id}".encode()).digest()
                            self.logger.warning("Using fallback key due to key exchange failure")
                    
                except (json.JSONDecodeError, UnicodeDecodeError) as e:
                    self.logger.warning(f"Could not parse response as JSON: {str(e)}. Raw data: {response_data[:100]!r}...")
                    self.logger.warning("Attempting to interpret as direct file transfer")
                    
                    
                    if len(response_data) >= 16:  
                        iv = response_data[:16]
                        encrypted_data = response_data[16:]
                        file_size = -1  
                        received_hash = ""
                        
                        peer_info = self.connected_peers.get(peer_id) or self.known_peers.get(peer_id, {})
                        fingerprint = peer_info.get('fingerprint', '')
                        if fingerprint:
                            key = hashlib.sha256(fingerprint.encode()).digest()
                        else:
                            key = hashlib.sha256(f"{self.user_id}:{peer_id}".encode()).digest()
                        
                        self.logger.debug("Using fallback key for direct transfer")
                    else:
                        self.logger.error("Response too short to contain a valid IV")
                        self.notify_file_transfer_status(file_name, 0, "failed", "Invalid response from peer")
                        return False
                
                
                if key is None:
                    self.logger.error("Failed to establish encryption key")
                    self.notify_file_transfer_status(file_name, 0, "failed", "Encryption key error")
                    return False
                    
                if iv is None or len(iv) != 16:
                    self.logger.error(f"Invalid IV received: {len(iv) if iv else 0} bytes")
                    self.notify_file_transfer_status(file_name, 0, "failed", "Invalid encryption IV")
                    return False
                
                # Rest of the download function remains largely unchanged
                self.logger.debug("Starting to receive encrypted data...")
                # Only continue receiving if we don't already have data from earlier
                if not encrypted_data:
                    bytes_received = 0
                    total_encrypted_size = file_size
                    
                    # Set a retry count and no-data counter to handle stalled connections
                    retries_left = 3
                    no_data_counter = 0
                    
                    with open(temp_path, 'wb') as f:
                        # Collect all encrypted data first
                        start_time = time.time()
                        
                        while (total_encrypted_size <= 0 or bytes_received < total_encrypted_size) and retries_left > 0:
                            try:
                                
                                remaining_bytes = total_encrypted_size - bytes_received if total_encrypted_size > 0 else 8192
                                if remaining_bytes > 0:
                                    # Set a dynamic timeout 
                                    dynamic_timeout = min(30, max(5, remaining_bytes / 10000))
                                    s.settimeout(dynamic_timeout)
                                
                                chunk = s.recv(8192)  
                                
                                if not chunk:
                                    no_data_counter += 1
                                    self.logger.warning(f"No data received (attempt {no_data_counter}/3)")
                                    if no_data_counter >= 3:
                                        self.logger.warning(f"Connection appears closed after receiving {bytes_received}/{total_encrypted_size} bytes")
                                        break
                                    time.sleep(0.5)  
                                    continue
                                else:
                                    # Reset the counter if we receive data
                                    no_data_counter = 0
                                
                                chunk_len = len(chunk)
                                bytes_received += chunk_len
                                encrypted_data += chunk
                                
                                # Calculate progress percentage
                                if total_encrypted_size > 0:
                                    progress = int(100 * bytes_received / total_encrypted_size)
                                else:
                                    progress = 50 
                                    
                                rate = bytes_received / (time.time() - start_time + 0.001)
                                self.logger.debug(f"Received chunk: {chunk_len} bytes, Total: {bytes_received}/{total_encrypted_size} ({progress}%), Rate: {rate:.2f} B/s")
                                self.notify_file_transfer_status(file_name, progress, "downloading")
                            except socket.timeout:
                                retries_left -= 1
                                self.logger.warning(f"Socket timeout, {retries_left} retries left. Received {bytes_received}/{total_encrypted_size}")
                                if retries_left <= 0:
                                    break
                                time.sleep(1)  
                        
                        # Accept incomplete downloads if we have most of the data (>99%)
                        if total_encrypted_size > 0 and bytes_received < total_encrypted_size:
                            completion_percentage = (bytes_received / total_encrypted_size) * 100
                            if completion_percentage >= 99.0:
                                self.logger.warning(f"Download almost complete: {completion_percentage:.2f}% ({bytes_received}/{total_encrypted_size} bytes).")
                            else:
                                self.logger.error(f"Incomplete download: received {bytes_received}/{total_encrypted_size} bytes ({completion_percentage:.2f}%)")
                                self.notify_file_transfer_status(file_name, int(completion_percentage), "failed", f"Incomplete download: {bytes_received}/{total_encrypted_size} bytes")
                                return False
                
                # Process the received data
                self.logger.debug(f"Download complete: received {len(encrypted_data)} bytes, now decrypting...")
                
                # Ensure we have data to decrypt
                if not encrypted_data:
                    self.logger.error("No encrypted data received")
                    self.notify_file_transfer_status(file_name, 0, "failed", "No data received")
                    return False
                
                # Decrypt the complete data
                try:
                    with open(temp_path, 'wb') as f:
                        self.logger.debug("Creating cipher with key and IV...")
                        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
                        decryptor = cipher.decryptor()
                        
                        self.logger.debug("Decrypting data...")
                        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
                        self.logger.debug(f"Decrypted data length: {len(decrypted_data)} bytes")
                        
                        # Remove padding
                        self.logger.debug("Removing padding...")
                        unpadder = padding.PKCS7(128).unpadder()
                        unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
                        self.logger.debug(f"Unpadded data length: {len(unpadded_data)} bytes")
                        
                        # Write the decrypted and unpadded data
                        self.logger.debug(f"Writing to {temp_path}...")
                        f.write(unpadded_data)
                        self.logger.debug("Successfully wrote unpadded data")
                        
                except Exception as e:
                    self.logger.exception(f"Decryption error: {str(e)}")
                    self.notify_file_transfer_status(file_name, 100, "failed", f"Decryption error: {str(e)}")
                    if os.path.exists(temp_path):
                        os.remove(temp_path)
                    return False
                
                # Re-encrypt with local key
                self.logger.debug("Re-encrypting with local key...")
                local_key = hashlib.sha256(self.auth_manager.generate_fingerprint().encode()).digest()
                try:
                    self._encrypt_file(temp_path, local_key)
                    self.logger.debug("Local encryption complete")
                except Exception as e:
                    self.logger.exception(f"Local encryption failed: {str(e)}")
                    self.notify_file_transfer_status(file_name, 100, "failed", f"Local encryption error: {str(e)}")
                    if os.path.exists(temp_path):
                        os.remove(temp_path)
                    return False
                
                # Verify hash if provided
                if file_hash or received_hash:
                    self.logger.debug("Verifying file hash...")
                    try:
                        with open(temp_path, 'rb') as f:
                            decrypted_content = self._decrypt_file(temp_path, local_key)
                            
                            actual_hash_hex = hashlib.sha256(decrypted_content).hexdigest()
                            
                            actual_hash_b64 = base64.b64encode(hashlib.sha256(decrypted_content).digest()).decode('utf-8')
                            
                        self.logger.debug(f"Calculated hash hex: {actual_hash_hex}")
                        self.logger.debug(f"Calculated hash b64: {actual_hash_b64}")
                        expected_hash = file_hash or received_hash
                        
                        if expected_hash:
                            # Determine the format of the expected hash
                            if len(expected_hash) == 64 and all(c in '0123456789abcdef' for c in expected_hash.lower()):
                                # It's a hex hash, compare with our hex hash
                                if actual_hash_hex.lower() != expected_hash.lower():
                                    self.logger.error(f"Hash verification failed (hex). Expected: {expected_hash}, Got: {actual_hash_hex}")
                                    self.notify_file_transfer_status(file_name, 100, "failed", "Hash verification failed")
                                    os.remove(temp_path)
                                    return False
                            else:
                                # Try base64 comparison
                                if actual_hash_b64 != expected_hash:
                                    # Try converting hex to base64 as last resort
                                    try:
                                        hex_bytes = bytes.fromhex(expected_hash)
                                        expected_hash_b64 = base64.b64encode(hex_bytes).decode('utf-8')
                                        if actual_hash_b64 != expected_hash_b64:
                                            self.logger.error(f"Hash verification failed after conversion. Expected: {expected_hash}, Got: {actual_hash_b64}")
                                            self.notify_file_transfer_status(file_name, 100, "failed", "Hash verification failed")
                                            os.remove(temp_path)
                                            return False
                                    except ValueError:
                                        self.logger.error(f"Hash verification failed. Expected: {expected_hash}, Got: {actual_hash_b64}")
                                        self.notify_file_transfer_status(file_name, 100, "failed", "Hash verification failed")
                                        os.remove(temp_path)
                                        return False
                            
                        self.logger.debug("Hash verification successful or skipped")
                    except Exception as e:
                        self.logger.exception(f"Hash verification failed: {str(e)}")
                        self.notify_file_transfer_status(file_name, 100, "failed", f"Hash verification error: {str(e)}")
                        os.remove(temp_path)
                        return False
                
                # Complete the download
                received_file_info = {
                    'name': file_name, 
                    'size': os.path.getsize(temp_path), 
                    'hash': received_hash or file_hash or "",
                    'source_peer': peer_id, 
                    'path': dest_path, 
                    'received_at': time.time(),
                    'origin': peer_id
                }
                self.received_files.append(received_file_info)
                os.rename(temp_path, dest_path)
                self.logger.info(f"Successfully completed download of {file_name} from {peer_id}")
                self.notify_file_transfer_status(file_name, 100, "completed")
                return True
                    
        except ValueError as e:
            self.logger.exception(f"ValueError in download: {str(e)}")
            self.notify_file_transfer_status(file_name, 0, "failed", f"Decryption error: {str(e)}")
        except socket.timeout:
            self.logger.error(f"Network timeout while downloading {file_name}")
            self.notify_file_transfer_status(file_name, 0, "failed", "Network timeout")
        except ConnectionError as e:
            self.logger.error(f"Connection error: {str(e)}")
            self.notify_file_transfer_status(file_name, 0, "failed", f"Connection failed: {str(e)}")
        except json.JSONDecodeError as e:
            self.logger.error(f"Invalid JSON response: {str(e)}")
            self.notify_file_transfer_status(file_name, 0, "failed", f"Invalid server response: {str(e)}")
        except Exception as e:
            self.logger.exception(f"Unexpected error in _download_file: {str(e)}")
            self.notify_file_transfer_status(file_name, 0, "failed", f"Unexpected error: {str(e)}")
        
        # Clean up temp file if it exists
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except:
                pass
        
        return False

    def _encrypt_file(self, file_path: str, key: bytes):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        with open(file_path, 'rb') as f_in, open(file_path + '.enc', 'wb') as f_out:
            f_out.write(iv)
            data = f_in.read()
            padded_data = padder.update(data) + padder.finalize()
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
            f_out.write(encrypted_data)
        os.replace(file_path + '.enc', file_path)

    def _decrypt_file(self, file_path: str, key: bytes) -> bytes:
        with open(file_path, 'rb') as f:
            iv = f.read(16)
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padder = padding.PKCS7(128).unpadder()
            encrypted_data = f.read()
            decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
            unpadded_data = padder.update(decrypted_data) + padder.finalize()
            return unpadded_data

    def _request_file_consent(self, peer_id: str, file_name: str) -> bool:
        self.logger.info(f"Consent requested for {file_name} from {peer_id}")
        return True  

    def _send_file(self, client_socket: socket.socket, file_name: str, key: bytes):
        """Send file with proper encryption and padding"""
        try:
            file_path = os.path.join(self.shared_files_dir, file_name)
            local_key = hashlib.sha256(self.auth_manager.generate_fingerprint().encode()).digest()
            
            # Generate a random IV
            iv = os.urandom(16)
            # First decrypt the locally stored file 
            try:
                decrypted_data = self._decrypt_file(file_path, local_key)
            except Exception as e:
                self.logger.error(f"Error decrypting file for sending: {e}")
                return False
            
            # Set up encryption with peer's session key
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            # Apply padding to the raw data
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(decrypted_data) + padder.finalize()
            
            # Encrypt with the session key
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
            
            # Send IV followed by encrypted data
            client_socket.sendall(iv + encrypted_data)
            
            self.logger.info(f"Sent file {file_name} ({len(encrypted_data)} bytes) with IV")
            return True
        except Exception as e:
            self.logger.error(f"Error in _send_file: {e}")
            return False

    def _get_file_hash(self, file_name: str) -> str:
        file_path = os.path.join(self.shared_files_dir, file_name)
        key = hashlib.sha256(self.auth_manager.generate_fingerprint().encode()).digest()
        return hashlib.sha256(self._decrypt_file(file_path, key)).hexdigest()

    def request_connection(self, peer_id: str) -> bool:
        if peer_id not in self.known_peers:
            self.logger.error(f"Connection request failed: Peer {peer_id} not found in known_peers")
            return False
        peer = self.known_peers[peer_id]
        self.logger.info(f"Attempting connection to {peer['username']} ({peer_id}) at {peer['host']}:{peer['port']}")
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(5)
                s.connect((peer['host'], peer['port']))
                message = {
                    'type': 'connection_request',
                    'sender_id': self.user_id,
                    'sender_name': self.username,
                    'sender_port': self.comm_port,
                    'fingerprint': self.auth_manager.generate_fingerprint(),
                    'requires_mutual': True
                }
                s.sendall(json.dumps(message).encode('utf-8') + b'\n')
                self.logger.info(f"Connection request sent to {peer_id}")
                return True  
        except socket.timeout:
            self.logger.error(f"Connection timeout to {peer_id} at {peer['host']}:{peer['port']}")
            return False
        except ConnectionRefusedError:
            self.logger.error(f"Connection refused by {peer_id} at {peer['host']}:{peer['port']}")
            return False
        except Exception as e:
            self.logger.error(f"Connection request failed to {peer_id}: {e}")
            return False

    def accept_connection(self, peer_id: str, verify_fingerprint: bool = True):
        request = next((r for r in self.pending_requests if r['peer_id'] == peer_id), None)
        if not request:
            self.logger.error(f"No pending request found for {peer_id}")
            return False
        if verify_fingerprint and request.get('fingerprint'):
            if not self.auth_manager.verify_peer(peer_id, request['fingerprint']):
                self.logger.error(f"Fingerprint verification failed for {peer_id}")
                return False
        self.pending_requests.remove(request)
        peer = self.known_peers[peer_id]
        peer['connected'] = True
        self.connected_peers[peer_id] = peer
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(5)
                s.connect((peer['host'], peer['port']))
                message = {
                    'type': 'connection_response',
                    'peer_id': self.user_id,  
                    'accepted': True,
                    'sender_id': self.user_id,
                    'sender_name': self.username,
                    'fingerprint': self.auth_manager.generate_fingerprint()
                }
                s.sendall(json.dumps(message).encode('utf-8') + b'\n')
                self.logger.info(f"Sent connection acceptance to {peer_id}")
            self.notify_connection_status_changed(peer_id, True)
            return True
        except Exception as e:
            self.logger.error(f"Failed to send acceptance to {peer_id}: {e}")
            return False

    def send_file(self, peer_id: str, file_name: str) -> bool:
        if peer_id not in self.connected_peers:
            return False
        peer = self.connected_peers[peer_id]
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((peer['host'], peer['port']))
                request = {
                    'type': 'file_download_request',
                    'sender_id': self.user_id,
                    'file_name': file_name,
                    'file_hash': self._get_file_hash(file_name),
                    'ephemeral_public': base64.b64encode(
                        ec.generate_private_key(ec.SECP384R1()).public_key().public_bytes(
                            encoding=serialization.Encoding.DER,
                            format=serialization.PublicFormat.SubjectPublicKeyInfo
                        )
                    ).decode('utf-8')
                }
                s.sendall(json.dumps(request).encode('utf-8') + b'\n')
                response = json.loads(s.recv(4096).decode('utf-8').strip())
                if response.get('status') == 'approved':
                    self._send_file(s, file_name, hashlib.sha256(
                        ec.generate_private_key(ec.SECP384R1()).exchange(
                            ec.ECDH(), serialization.load_der_public_key(base64.b64decode(response['ephemeral_public']))
                        )
                    ).digest())
                    self.notify_file_transfer_status(file_name, 100, "completed")
                    return True
                else:
                    self.notify_file_transfer_status(file_name, 0, "failed", "Peer denied request")
                    return False
        except Exception as e:
            self.logger.error(f"Send file failed: {e}")
            return False

    def notify_key_change(self):
        new_fingerprint = self.auth_manager.generate_fingerprint()
        self.logger.info(f"Generated new fingerprint: {new_fingerprint}")
        if not self.connected_peers:
            self.logger.warning("No connected peers to notify of key change")
            return
        for peer_id, peer in self.connected_peers.items():
            for attempt in range(3):  # Retry up to 3 times
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(10)  
                        s.connect((peer['host'], peer['port']))
                        message = {
                            'type': 'key_change_notification',
                            'sender_id': self.user_id,
                            'sender_name': self.username,
                            'new_fingerprint': new_fingerprint
                        }
                        s.sendall(json.dumps(message).encode('utf-8') + b'\n')
                        self.logger.info(f"Notified {peer['username']} ({peer_id}) of new fingerprint")
                        break
                except Exception as e:
                    self.logger.error(f"Attempt {attempt + 1} failed to notify {peer_id}: {e}")
                    if attempt == 2:
                        self.logger.error(f"Failed to notify {peer_id} after 3 attempts")
                    time.sleep(1)

    def add_verified_peer(self, peer_name: str, fingerprint: str) -> str:
        peer_id = str(uuid.uuid4())
        self.auth_manager.verify_peer(peer_id, fingerprint)
        self.known_peers[peer_id] = {
            'username': peer_name, 'id': peer_id, 'fingerprint': fingerprint, 'connected': False
        }
        return peer_id

    def notify_peer_discovered(self, peer: Dict):
        pass

    def notify_connection_request(self, request: Dict):
        pass

    def notify_connection_status_changed(self, peer_id: str, connected: bool):
        pass

    def notify_file_transfer_status(self, file_name: str, progress: int, status: str, error_msg: str = ""):
        pass

    def close(self):
        self.running = False
        self.zconf.close()
        self.server_socket.close()

class P2PServiceListener:
    def __init__(self, client):
        self.client = client

    def add_service(self, zconf, type, name):
        info = zconf.get_service_info(type, name)
        if not info:
            return
        properties = {k.decode('utf-8'): v.decode('utf-8') for k, v in info.properties.items()}
        peer_id = properties.get('user_id', f"unknown-{name}")
        if peer_id == self.client.user_id:
            return
        if peer_id not in self.client.known_peers:
            self.client.known_peers[peer_id] = {
                'username': properties.get('username', 'Unknown'),
                'host': info.parsed_addresses()[0],
                'port': info.port,
                'id': peer_id,
                'connected': False
            }
            self.client.notify_peer_discovered(self.client.known_peers[peer_id])

    def remove_service(self, zconf, type, name):
        peer_id = name.split('.')[0].split('-')[0]
        if peer_id in self.client.known_peers and peer_id != self.client.user_id:
            del self.client.known_peers[peer_id]
            if peer_id in self.client.connected_peers:
                del self.client.connected_peers[peer_id]

    def update_service(self, zconf, type, name):
        pass