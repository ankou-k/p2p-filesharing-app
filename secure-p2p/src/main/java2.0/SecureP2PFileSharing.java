import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.KeyAgreement;
import javax.jmdns.JmDNS;
import javax.jmdns.ServiceEvent;
import javax.jmdns.ServiceInfo;
import javax.jmdns.ServiceListener;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.logging.Logger;

public class SecureP2PFileSharing {
    private String username;
    private String userId;
    private String dataDir;
    private AuthenticationManager authManager;
    private Logger logger;
    private ServerSocket serverSocket;
    private int commPort;
    private Map<String, Map<String, Object>> knownPeers;
    private Map<String, Map<String, Object>> connectedPeers;
    private List<Map<String, Object>> pendingRequests;
    private List<Map<String, Object>> sharedFiles;
    private List<Map<String, Object>> receivedFiles;
    private String receivedFilesDir;
    private String sharedFilesDir;
    private volatile boolean running;
    private JmDNS jmdns;
    private Gson gson = new Gson();

    public interface NotifyCallback {
        void notify(Map<String, Object> data);
    }

    public interface StatusCallback {
        void notify(String peerId, boolean connected);
    }

    public interface FileTransferCallback {
        void notify(String fileName, int progress, String status, String errorMsg);
    }

    public NotifyCallback notifyPeerDiscovered = data -> {};
    public NotifyCallback notifyConnectionRequest = data -> {};
    public StatusCallback notifyConnectionStatusChanged = (peerId, connected) -> {};
    public FileTransferCallback notifyFileTransferStatus = (fileName, progress, status, errorMsg) -> {};

    public SecureP2PFileSharing(String username, int port, String dataDir) throws IOException {
        this.username = username;
        this.userId = UUID.randomUUID().toString();
        this.dataDir = dataDir != null ? dataDir : new File("p2p_data").getAbsolutePath();
        new File(this.dataDir).mkdirs();
        this.authManager = new AuthenticationManager(username, this.dataDir);
        this.logger = Logger.getLogger("P2P-" + username);

        this.serverSocket = new ServerSocket(port);
        this.commPort = serverSocket.getLocalPort();
        this.knownPeers = new HashMap<>();
        this.connectedPeers = new HashMap<>();
        this.pendingRequests = new ArrayList<>();
        this.sharedFiles = new ArrayList<>();
        this.receivedFiles = new ArrayList<>();
        this.receivedFilesDir = new File(dataDir, "received").getAbsolutePath();
        this.sharedFilesDir = new File(dataDir, "shared").getAbsolutePath();
        new File(receivedFilesDir).mkdirs();
        new File(sharedFilesDir).mkdirs();

        this.running = true;
        startCommThread();
        startMdnsDiscovery();
    }

    private void startCommThread() {
        new Thread(this::communicationLoop, "CommThread").start();
        logger.info("Started communication thread");
    }

    private void communicationLoop() {
        while (running) {
            try (Socket clientSocket = serverSocket.accept()) {
                // Configure socket properties
                clientSocket.setTcpNoDelay(true);  // Disable Nagle's algorithm
                clientSocket.setKeepAlive(true);   // Enable TCP keepalive
                clientSocket.setSoTimeout(60000);  // 60-second timeout
                
                try {
                    BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
                    String messageData = in.readLine();
                    if (messageData != null) {
                        Map<String, Object> message = gson.fromJson(messageData, new TypeToken<Map<String, Object>>(){}.getType());
                        handleMessage(message, clientSocket);
                    }
                } catch (com.google.gson.JsonSyntaxException e) {
                    logger.warning("Received malformed JSON: " + e.getMessage());
                } catch (Exception e) {
                    if (running) logger.severe("Message handling error: " + e.getMessage());
                }
            } catch (Exception e) {
                if (running) logger.severe("Comm loop error: " + e.getMessage());
            }
        }
    }

    private void handleMessage(Map<String, Object> message, Socket clientSocket) throws Exception {
        String msgType = (String) message.get("type");
        InetSocketAddress addr = (InetSocketAddress) clientSocket.getRemoteSocketAddress();
        switch (msgType) {
            case "connection_request":
                handleConnectionRequest(message, addr);
                break;
            case "connection_response":
                handleConnectionResponse(message);
                break;
            case "list_files_request":
                handleListFilesRequest(message, clientSocket);
                break;
            case "file_download_request":
                handleFileDownloadRequest(message, clientSocket);
                break;
            case "key_change_notification":
                handleKeyChangeNotification(message);
                break;
            default:
                logger.warning("Unknown message type: " + msgType);
        }
    }

    private void handleConnectionRequest(Map<String, Object> message, InetSocketAddress addr) {
        String senderId = (String) message.get("sender_id");
        String senderName = (String) message.getOrDefault("sender_name", "Unknown");
        String senderHost = addr.getHostString();
        int senderPort = ((Double) message.getOrDefault("sender_port", (double) commPort)).intValue();
        String senderFingerprint = (String) message.getOrDefault("fingerprint", "");
        boolean requiresMutual = (Boolean) message.getOrDefault("requires_mutual", false);

        Map<String, Object> peer = knownPeers.get(senderId);
        if (peer == null) {
            peer = new HashMap<>();
            peer.put("username", senderName);
            peer.put("host", senderHost);
            peer.put("port", senderPort);
            peer.put("id", senderId);
            peer.put("connected", false);
            peer.put("fingerprint", senderFingerprint);
            knownPeers.put(senderId, peer);
            notifyPeerDiscovered.notify(peer);
            logger.info("Added new peer: " + senderName + " (" + senderId + ")");
        } else {
            // Update existing peer
            peer.put("username", senderName);
            peer.put("host", senderHost);
            peer.put("port", senderPort);
            peer.put("fingerprint", senderFingerprint);
            logger.info("Updated peer info: " + senderName + " (" + senderId + ")");
        }

        Map<String, Object> request = new HashMap<>();
        request.put("peer_id", senderId);
        request.put("peer_name", senderName);
        request.put("host", senderHost);
        request.put("port", senderPort);
        request.put("timestamp", System.currentTimeMillis() / 1000.0);
        request.put("fingerprint", senderFingerprint);
        if (!pendingRequests.contains(request)) {
            pendingRequests.add(request);
            logger.info("Received connection request from " + senderName + " (" + senderId + ")");
            notifyConnectionRequest.notify(request);
        }
    }

    private void handleConnectionResponse(Map<String, Object> message) {
        String senderId = (String) message.get("sender_id");
        boolean accepted = (Boolean) message.getOrDefault("accepted", false);
        String senderFingerprint = (String) message.getOrDefault("fingerprint", "");
        if (knownPeers.containsKey(senderId) && accepted) {
            if (authManager.verifyPeer(senderId, senderFingerprint)) {
                connectedPeers.put(senderId, knownPeers.get(senderId));
                knownPeers.get(senderId).put("connected", true);
                notifyConnectionStatusChanged.notify(senderId, true);
                logger.info("Connection accepted by " + senderId + " with verified fingerprint");
            } else {
                logger.severe("Fingerprint verification failed for " + senderId);
            }
        } else if (!accepted) {
            logger.info("Connection rejected by " + senderId);
        }
    }

    private void handleListFilesRequest(Map<String, Object> message, Socket clientSocket) throws IOException {
        String senderId = (String) message.get("user_id");
        String requestId = (String) message.getOrDefault("request_id", "unknown");
        if (connectedPeers.containsKey(senderId) || knownPeers.containsKey(senderId)) {
            List<Map<String, Object>> fileList = listSharedFiles();
            Map<String, Object> response = new HashMap<>();
            response.put("type", "list_files_response");
            response.put("files", fileList);
            response.put("request_id", requestId);
            PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
            out.println(gson.toJson(response));
        }
    }

    private void sendDenialResponse(Socket clientSocket, String fileName, String reason, String senderId) {
        try {
            Map<String, Object> response = new HashMap<>();
            response.put("type", "file_download_response");
            response.put("status", "denied");
            response.put("file_name", fileName);
            response.put("file_size", 0);
            response.put("reason", reason);
            
            String jsonResponse = gson.toJson(response) + "\n";
            try (BufferedWriter writer = new BufferedWriter(
                    new OutputStreamWriter(clientSocket.getOutputStream()))) {
                writer.write(jsonResponse);
                writer.flush();
                logger.info("Sent denial response to " + senderId + ": " + reason);
            }
        } catch (Exception e) {
            logger.severe("Failed to send denial response: " + e.getMessage());
        }
    }

    private void handleFileDownloadRequest(Map<String, Object> message, Socket clientSocket) throws Exception {
        String senderId = (String) message.get("sender_id");
        String fileName = (String) message.get("file_name");
        
        // Sanitize filename to avoid special character issues
        String sanitizedFileName = fileName.replace("#", "%23");
        
        // Log the request info
        logger.info("File download request from " + senderId + " for file " + sanitizedFileName);
        
        // Check shared file path exists
        File requestedFile = new File(sharedFilesDir, fileName);
        if (!requestedFile.exists()) {
            logger.warning("Requested file does not exist: " + requestedFile.getAbsolutePath());
            sendDenialResponse(clientSocket, fileName, "File not found", senderId);
            return;
        }
        // Check if sender is a connected peer
        if (connectedPeers.containsKey(senderId)) {
            // Request consent to share the file with this peer
            boolean consent = requestFileConsent(senderId, fileName);
            
            // Generate ephemeral key pair for this exchange
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(new ECGenParameterSpec("secp384r1"));
            KeyPair kp = kpg.generateKeyPair();
            ECPrivateKey privateKey = (ECPrivateKey) kp.getPrivate();
            ECPublicKey publicKey = (ECPublicKey) kp.getPublic();
            
            // Process peer's public key
            String peerKeyString = (String) message.get("ephemeral_public");
            logger.fine("Received public key from " + senderId + ", format: " + 
                        (peerKeyString != null && peerKeyString.contains("BEGIN PUBLIC KEY") ? "PEM" : "Raw Base64"));
            
            ECPublicKey peerPublic = null;
            try {
                peerPublic = processPublicKey(peerKeyString);
            } catch (Exception e) {
                logger.severe("Failed to process peer's public key: " + e.getMessage());
                throw e;
            }
            
            // Generate shared key
            KeyAgreement ka = KeyAgreement.getInstance("ECDH");
            ka.init(privateKey);
            ka.doPhase(peerPublic, true);
            byte[] sharedKey = MessageDigest.getInstance("SHA-256").digest(ka.generateSecret());
            
            // Create response
            Map<String, Object> response = new HashMap<>();
            response.put("type", "file_download_response");
            response.put("status", consent ? "approved" : "denied");
            response.put("file_name", fileName);
            response.put("file_size", consent ? new File(sharedFilesDir, fileName).length() : 0);
            response.put("file_hash", consent ? getFileHash(fileName) : "");
            
            // Format public key as raw DER base64 for Python compatibility
            String ephemeralKey = Base64.getEncoder().encodeToString(publicKey.getEncoded());
            response.put("ephemeral_public", ephemeralKey);

            
            String jsonResponse = gson.toJson(response) + "\n";  
            logger.info("Sending response for " + fileName + " to " + senderId + ": " + 
                    (consent ? "approved" : "denied") + " (JSON length: " + jsonResponse.length() + ")");

            
            BufferedWriter writer = new BufferedWriter(
            new OutputStreamWriter(clientSocket.getOutputStream()));
            writer.write(jsonResponse);
            writer.flush();
            logger.fine("Response bytes written: " + jsonResponse.getBytes().length);
            
            
            Thread.sleep(100);
            
            // Send file if consent was granted
            if (consent) {
                logger.info("Starting to send file " + fileName + " to " + senderId);
                sendFile(clientSocket, fileName, sharedKey);
            }
            
        } else {
            // Handle non-connected peer case
            logger.warning("File download request from non-connected peer: " + senderId);
            
            // Create rejection response
            Map<String, Object> response = new HashMap<>();
            response.put("type", "file_download_response");
            response.put("status", "denied");
            response.put("file_name", fileName);
            response.put("file_size", 0);
            response.put("reason", "Peer not connected");
            
            // Send response with proper newline termination
            String jsonResponse = gson.toJson(response) + "\n";
            
            try (BufferedWriter writer = new BufferedWriter(
                    new OutputStreamWriter(clientSocket.getOutputStream()))) {
                writer.write(jsonResponse);
                writer.flush();
                logger.info("Sent denial response to non-connected peer " + senderId);
            } catch (Exception e) {
                logger.severe("Failed to send denial response: " + e.getMessage());
            }
        }
    }

    private void handleKeyChangeNotification(Map<String, Object> message) {
        String senderId = (String) message.get("sender_id");
        String senderName = (String) message.getOrDefault("sender_name", "Unknown");
        String newFingerprint = (String) message.get("new_fingerprint");
        logger.info("Received key change notification from " + senderName + " (" + senderId + "): " + newFingerprint);
        if (connectedPeers.containsKey(senderId)) {
            authManager.verifyPeer(senderId, newFingerprint);
            notifyConnectionStatusChanged.notify(senderId, true);
            logger.info("Updated fingerprint for " + senderId);
        } else {
            logger.warning("Ignored key change from " + senderId + ": not a connected peer");
        }
    }

    private InetAddress getLocalIPAddress() throws IOException {
        try {
            
            try (DatagramSocket socket = new DatagramSocket()) {
                socket.connect(InetAddress.getByName("8.8.8.8"), 10002);
                InetAddress localAddress = socket.getLocalAddress();
                if (localAddress.isAnyLocalAddress()) {
                    throw new IOException("Could not determine local address");
                }
                return localAddress;
            }
        } catch (Exception e) {
            logger.warning("Failed to determine network interface with external connectivity: " + e.getMessage());
           
            return InetAddress.getLocalHost();
        }
    }

    private void startMdnsDiscovery() throws IOException {

        InetAddress localAddress = getLocalIPAddress();
        logger.info("Using local IP address: " + localAddress.getHostAddress());

        jmdns = JmDNS.create(localAddress);
        String serviceType = "_securep2p._tcp.local.";
        
        
        Map<String, String> props = new HashMap<>();
        props.put("user_id", userId);
        props.put("username", username);
        
        // Create service 
        ServiceInfo serviceInfo = ServiceInfo.create(
            serviceType,           // Service type
            userId.substring(0, 8) + "-" + username,  // Service name
            commPort,              // Port
            0,                     // Weight
            0,                     // Priority
            props                  // Properties as Map
        );
        
        jmdns.registerService(serviceInfo);
        logger.info("Registered service: " + userId + " with username " + username);
        
        // Add service listener
        jmdns.addServiceListener(serviceType, new ServiceListener() {
            @Override
            public void serviceAdded(ServiceEvent event) {
                ServiceInfo info = jmdns.getServiceInfo(event.getType(), event.getName());
                if (info != null) addPeerFromService(info);
            }
    
            @Override
            public void serviceRemoved(ServiceEvent event) {
                String name = event.getName();
                // Extract just the ID part before any hyphen
                String peerId = name.contains("-") ? name.substring(0, name.indexOf("-")) : name;
                if (peerId.length() > 36) peerId = peerId.substring(0, 36);  // Ensure it's not longer than UUID
                
                if (knownPeers.containsKey(peerId) && !peerId.equals(userId)) {
                    knownPeers.remove(peerId);
                    connectedPeers.remove(peerId);
                    notifyConnectionStatusChanged.notify(peerId, false);
                }
            }
    
            @Override
            public void serviceResolved(ServiceEvent event) {}
        });
    }

    private void addPeerFromService(ServiceInfo info) {
        // First check if it's our own service
        if (info.getName().contains(userId.substring(0, 8))) {
            logger.fine("Ignoring own service: " + info.getName());
            return;
        }
        
        // Extract properties properly
        String peerId = info.getPropertyString("user_id");
        String peerUsername = info.getPropertyString("username");
        
        // Double-check it's not self
        if (peerId == null || peerId.equals(userId)) {
            logger.fine("Ignoring self or invalid peer: " + info.getName());
            return;
        }
        
        // Ensure username is valid
        if (peerUsername == null || peerUsername.isEmpty()) {
            logger.warning("Peer has no username: " + peerId);
            peerUsername = "Unknown_" + peerId.substring(0, 6);
        }
        
        // Add or update peer info
        Map<String, Object> existingPeer = knownPeers.get(peerId);
        if (existingPeer == null) {
            Map<String, Object> peer = new HashMap<>();
            peer.put("username", peerUsername);
            peer.put("host", info.getInetAddresses()[0].getHostAddress());
            peer.put("port", info.getPort());
            peer.put("id", peerId);
            peer.put("connected", false);
            knownPeers.put(peerId, peer);
            notifyPeerDiscovered.notify(peer);
            logger.info("Discovered new peer: " + peerUsername + " (" + peerId + ")");
        } else {
            // Update existing peer info if changed
            String newUsername = info.getPropertyString("username");
            String newHost = info.getInetAddresses()[0].getHostAddress();
            int newPort = info.getPort();
            if (!newUsername.equals(existingPeer.get("username")) || !newHost.equals(existingPeer.get("host")) || !Objects.equals(newPort, existingPeer.get("port"))) {
                existingPeer.put("username", newUsername);
                existingPeer.put("host", newHost);
                existingPeer.put("port", newPort);
                notifyPeerDiscovered.notify(existingPeer);
                logger.info("Updated peer info from mDNS: " + newUsername + " (" + peerId + ")");
            }
        }
    }

    public List<Map<String, Object>> getDiscoveredPeers() {
        // Filter out self from the returned list
        return knownPeers.entrySet().stream()
            .filter(entry -> !entry.getKey().equals(userId))  // Filter out self
            .map(Map.Entry::getValue)
            .collect(java.util.stream.Collectors.toList());
    }

    public boolean addSharedFile(String filePath) {
        try {
            File file = new File(filePath);
            if (!file.exists() || !file.isFile()) {
                logger.severe("File not found: " + filePath);
                return false;
            }
    
            String fileName = file.getName();
            long fileSize = file.length();
    
            // Create shared files directory if it doesn't exist
            File sharedDir = new File(sharedFilesDir);  
            if (!sharedDir.exists() && !sharedDir.mkdirs()) {
                logger.severe("Failed to create shared directory: " + sharedDir.getAbsolutePath());
                return false;
            }
            
            // Log the paths being used
            logger.info("Adding file to share - Source: " + filePath);
            logger.info("Destination directory: " + sharedDir.getAbsolutePath());
            
            // Copy to shared directory
            File destFile = new File(sharedDir, fileName);
            logger.info("Will copy to: " + destFile.getAbsolutePath());
            
            Files.copy(file.toPath(), destFile.toPath(), java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            
            // Verify the file was copied
            if (!destFile.exists()) {
                logger.severe("File copy failed - destination file doesn't exist after copy");
                return false;
            }
            
            // Calculate hash from the original file
            String fileHash = Base64.getEncoder().encodeToString(
                MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(file.toPath()))
            );
            
            // Now encrypt the file in the shared directory
            byte[] key = MessageDigest.getInstance("SHA-256")
                .digest(authManager.generateFingerprint().getBytes(StandardCharsets.UTF_8));
            encryptFile(destFile.getAbsolutePath(), key);
            
            // Verify the file still exists after encryption
            if (!destFile.exists()) {
                logger.severe("File doesn't exist after encryption");
                return false;
            }
            
            // Add to shared files list with the hex hash format for Python compatibility
            Map<String, Object> fileInfo = new HashMap<>();
            // Convert base64 hash to hex format
            byte[] hashBytes = MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(file.toPath()));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hashBytes) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            
            fileInfo.put("hash", hexString.toString());
            fileInfo.put("name", fileName);
            fileInfo.put("size", fileSize);
            fileInfo.put("origin", userId);
            sharedFiles.add(fileInfo);
            
            logger.info("Successfully added shared file: " + fileName + " to " + destFile.getAbsolutePath());
            return true;
        } catch (Exception e) {
            logger.log(java.util.logging.Level.SEVERE, "Error adding shared file: " + e.getMessage(), e);
            e.printStackTrace();
            return false;
        }
    }

    public List<Map<String, Object>> listSharedFiles() {
        // First return any files already added to the in-memory list
        if (!sharedFiles.isEmpty()) {
            return new ArrayList<>(sharedFiles);
        }
        
        // Only scan directory if in-memory list is empty
        List<Map<String, Object>> files = new ArrayList<>();
        byte[] key;
        try {
            key = MessageDigest.getInstance("SHA-256").digest(authManager.generateFingerprint().getBytes());
        } catch (NoSuchAlgorithmException e) {
            logger.severe("Key generation failed: " + e.getMessage());
            return files;
        }
        
        File dir = new File(sharedFilesDir);
        if (!dir.exists()) {
            logger.warning("Shared directory doesn't exist: " + sharedFilesDir);
            return files;
    }
        
        File[] fileList = dir.listFiles();
        if (fileList == null) {
            logger.warning("Failed to list files in directory: " + sharedFilesDir);
            return files;
        }
        
        for (File file : fileList) {
            if (!file.isFile()) continue;
            
            
            if (file.getName().endsWith(".enc") || file.getName().endsWith(".part") || 
                file.getName().endsWith(".tmp")) {
                continue;
            }
            
            try {
                // Check if file has minimum size for encrypted content
                if (file.length() <= 16) {
                    logger.warning("Skipping file too small to be valid encrypted content: " + file.getName());
                    continue;
                }
                
                // Try to decrypt the file
                try {
                    byte[] decryptedData = decryptFile(file.getAbsolutePath(), key);
                    String fileHash = Base64.getEncoder().encodeToString(
                        MessageDigest.getInstance("SHA-256").digest(decryptedData));
                    
                    Map<String, Object> fileInfo = new HashMap<>();
                    fileInfo.put("hash", fileHash);
                    fileInfo.put("name", file.getName());
                    fileInfo.put("size", file.length());
                    fileInfo.put("origin", userId);
                    files.add(fileInfo);
                } catch (Exception e) {
                    logger.warning("Skipping file " + file.getName() + " - decryption failed: " + e.getMessage());
                   
                }
            } catch (Exception e) {
                logger.warning("Error processing file " + file.getName() + ": " + e.getMessage());
            }
        }
        
        return files;
    }

    public List<Map<String, Object>> getFilesFromPeer(String peerId, String fileHash) {
        if (fileHash != null) {
            for (Map.Entry<String, Map<String, Object>> entry : connectedPeers.entrySet()) {
                List<Map<String, Object>> files = requestFileList((String) entry.getValue().get("host"), (Integer) entry.getValue().get("port"));
                for (Map<String, Object> file : files) {
                    if (file.get("hash").equals(fileHash)) {
                        requestFileDownload(entry.getKey(), (String) file.get("name"), fileHash);
                        return Collections.singletonList(file);
                    }
                }
            }
            return Collections.emptyList();
        }
        if (!connectedPeers.containsKey(peerId) && !knownPeers.containsKey(peerId)) return Collections.emptyList();
        Map<String, Object> peer = connectedPeers.getOrDefault(peerId, knownPeers.get(peerId));
        return requestFileList((String) peer.get("host"), (Integer) peer.get("port"));
    }

    private List<Map<String, Object>> requestFileList(String host, int port) {
        try (Socket s = new Socket(host, port)) {
            s.setSoTimeout(15000);
            PrintWriter out = new PrintWriter(s.getOutputStream(), true);
            Map<String, Object> request = new HashMap<>();
            request.put("type", "list_files_request");
            request.put("user_id", userId);
            request.put("request_id", UUID.randomUUID().toString());
            out.println(gson.toJson(request));
            BufferedReader in = new BufferedReader(new InputStreamReader(s.getInputStream()));
            String response = in.readLine();
            Map<String, Object> resp = gson.fromJson(response, new TypeToken<Map<String, Object>>(){}.getType());
            if ("list_files_response".equals(resp.get("type"))) {
                return (List<Map<String, Object>>) resp.get("files");
            }
            return Collections.emptyList();
        } catch (Exception e) {
            logger.severe("Error requesting file list: " + e.getMessage());
            return Collections.emptyList();
        }
    }

    public boolean requestFileDownload(String peerId, String fileName, String fileHash) {
        if (!connectedPeers.containsKey(peerId) && !knownPeers.containsKey(peerId)) return false;
        Map<String, Object> peer = connectedPeers.getOrDefault(peerId, knownPeers.get(peerId));
        new Thread(() -> downloadFile((String) peer.get("host"), (Integer) peer.get("port"), peerId, fileName, fileHash), "DownloadThread").start();
        return true;
    }

    private void downloadFile(String host, int port, String peerId, String fileName, String fileHash) {
        try {
            notifyFileTransferStatus.notify(fileName, 0, "started", null);
            logger.info("Starting download of " + fileName + " from " + peerId + " at " + host + ":" + port);
    
            // Check if the peer exists at all
            Map<String, Object> peer = null;
            if (connectedPeers.containsKey(peerId)) {
                peer = connectedPeers.get(peerId);
            } else if (knownPeers.containsKey(peerId)) {
                peer = knownPeers.get(peerId);
            }
            
            if (peer == null) {
                logger.severe("Cannot find peer with ID: " + peerId);
                notifyFileTransferStatus.notify(fileName, 0, "failed", "Unknown peer");
                return;
            }
    
            try (Socket s = new Socket()) {
                // Set connection timeout and connect
                s.connect(new InetSocketAddress(host, port), 15000);
                s.setSoTimeout(60000);  
                
                // Generate ephemeral key pair for this exchange
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
                kpg.initialize(new ECGenParameterSpec("secp384r1"));
                KeyPair kp = kpg.generateKeyPair();
                ECPrivateKey privateKey = (ECPrivateKey) kp.getPrivate();
                ECPublicKey publicKey = (ECPublicKey) kp.getPublic();
                
                // Create request message
                Map<String, Object> request = new HashMap<>();
                request.put("type", "file_download_request");
                request.put("sender_id", userId);
                request.put("file_name", fileName);
                request.put("file_hash", fileHash);
                
                // Format public key as raw DER base64 for Python compatibility
                String rawEncodedKey = Base64.getEncoder().encodeToString(publicKey.getEncoded());
                request.put("ephemeral_public", rawEncodedKey);
                
                // Send request with proper line ending
                BufferedWriter writer = new BufferedWriter(
                    new OutputStreamWriter(s.getOutputStream(), StandardCharsets.UTF_8));
                writer.write(gson.toJson(request));
                writer.write("\n");
                writer.flush();
                logger.fine("Sent download request for: " + fileName);
    
                // Read and parse response with retry logic
                BufferedReader in = new BufferedReader(new InputStreamReader(s.getInputStream()));
                int tries = 0;
                String responseText = null;
                while (responseText == null && tries < 5) {
                    try {
                        responseText = in.readLine();
                    } catch (SocketTimeoutException e) {
                        logger.warning("Socket read timed out");
                        break;
                    }
                    
                    if (responseText == null) {
                        tries++;
                        logger.warning("Got empty response, retrying (" + tries + "/5)");
                        try {
                            Thread.sleep(200); 
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                        }
                    }
                }
                
                if (responseText == null || responseText.isEmpty()) {
                    throw new IOException("Empty response received after " + tries + " attempts");
                }
                
                Map<String, Object> response;
                try {
                    response = gson.fromJson(responseText, new TypeToken<Map<String, Object>>(){}.getType());
                } catch (Exception e) {
                    logger.severe("Error parsing JSON response: " + e.getMessage());
                    logger.severe("Response text was: " + responseText);
                    throw e;
                }
                
                if (!"approved".equals(response.get("status"))) {
                    String reason = (String) response.getOrDefault("reason", "unknown");
                    logger.warning("Download rejected: " + reason);
                    notifyFileTransferStatus.notify(fileName, 0, "failed", "Download rejected: " + reason);
                    return;
                }
    
                // Process peer's public key
                ECPublicKey peerPublic;
                try {
                    peerPublic = processPublicKey((String) response.get("ephemeral_public"));
                } catch (Exception e) {
                    logger.severe("Failed to process response public key: " + e.getMessage());
                    notifyFileTransferStatus.notify(fileName, 0, "failed", "Key exchange failed");
                    throw e;
                }
                
                // Generate shared key for encryption
                KeyAgreement ka = KeyAgreement.getInstance("ECDH");
                ka.init(privateKey);
                ka.doPhase(peerPublic, true);
                byte[] sharedKey = MessageDigest.getInstance("SHA-256").digest(ka.generateSecret());
                
                // Extract file information
                long fileSize = ((Number) response.getOrDefault("file_size", 0)).longValue();
                String receivedHash = (String) response.get("file_hash");
                String destPath = new File(receivedFilesDir, fileName).getAbsolutePath();
                String tempPath = destPath + ".part";
                
                logger.info("Downloading file: " + fileName + " (" + fileSize + " bytes)");
    
                // Create a DataInputStream for more robust binary reading
                DataInputStream dataIn = new DataInputStream(s.getInputStream());
                
                // Receive IV (16 bytes for AES)
                byte[] iv = new byte[16];
                try {
                    dataIn.readFully(iv);
                } catch (EOFException e) {
                    throw new IOException("Failed to read complete IV: " + e.getMessage());
                }
    
                // Receive encrypted data with progress tracking
                byte[] buffer = new byte[8192];
                int bytesReceived = 0;
                int progress = 0;
                
                try (FileOutputStream fos = new FileOutputStream(tempPath)) {
                    // First write the IV
                    fos.write(iv);
                    
                    // Then read and write the encrypted data
                    int bytesRead;
                    while ((bytesRead = dataIn.read(buffer)) != -1) {
                        fos.write(buffer, 0, bytesRead);
                        bytesReceived += bytesRead;
                        
                        // Update progress
                        int newProgress = fileSize > 0 ? (int)(100 * bytesReceived / fileSize) : 0;
                        if (newProgress > progress) {
                            progress = newProgress;
                            notifyFileTransferStatus.notify(fileName, progress, "downloading", "");
                        }
                    }
                }
                
                logger.info("Received encrypted file: " + bytesReceived + " bytes");
                
                // Rest of the decryption, verification and saving process
                try {
                    // Decrypt using the received IV and shared key
                    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                    cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(sharedKey, "AES"), new IvParameterSpec(iv));
                    
                
                    byte[] fileContent = Files.readAllBytes(new File(tempPath).toPath());
                    byte[] encryptedContent = new byte[fileContent.length - 16];
                    System.arraycopy(fileContent, 16, encryptedContent, 0, encryptedContent.length);
                    
                    // Decrypt and write to final file
                    byte[] decryptedContent = cipher.doFinal(encryptedContent);
                    try (FileOutputStream fos = new FileOutputStream(destPath)) {
                        fos.write(decryptedContent);
                    }
                    
                    // Verify hash if provided
                    if (fileHash != null && !fileHash.isEmpty()) {
                        // Calculate hash in hexadecimal format to match Python client
                        byte[] hashBytes = MessageDigest.getInstance("SHA-256").digest(decryptedContent);
                        StringBuilder hexString = new StringBuilder();
                        for (byte b : hashBytes) {
                            String hex = Integer.toHexString(0xff & b);
                            if (hex.length() == 1) hexString.append('0');
                            hexString.append(hex);
                        }
                        String actualHash = hexString.toString();
                            
                        if (!actualHash.equals(fileHash)) {
                            logger.warning("Hash verification failed: expected=" + fileHash + ", actual=" + actualHash);
                            notifyFileTransferStatus.notify(fileName, 100, "failed", "Hash verification failed");
                            new File(tempPath).delete();
                            new File(destPath).delete();
                            return;
                        }
                    }
                    
                    // Add file to received files list
                    Map<String, Object> fileInfo = new HashMap<>();
                    fileInfo.put("name", fileName);
                    fileInfo.put("size", decryptedContent.length);
                    fileInfo.put("hash", fileHash != null ? fileHash : receivedHash);
                    fileInfo.put("path", destPath);
                    fileInfo.put("source_peer", peerId);
                    fileInfo.put("received_at", System.currentTimeMillis());
                    
                    receivedFiles.add(fileInfo);
                    
                    // Remove temporary file
                    new File(tempPath).delete();
                    
                    notifyFileTransferStatus.notify(fileName, 100, "completed", "");
                    logger.info("Download completed: " + fileName);
                } catch (Exception e) {
                    logger.severe("Decryption error: " + e.getMessage());
                    notifyFileTransferStatus.notify(fileName, 0, "failed", "Decryption failed: " + e.getMessage());
                    new File(tempPath).delete();
                    throw e;
                }
            }
        } catch (Exception e) {
            logger.severe("Download failed: " + e.getMessage());
            e.printStackTrace();
            notifyFileTransferStatus.notify(fileName, 0, "failed", e.getMessage());
        }
    }

    private ECPublicKey processPublicKey(String keyString) throws Exception {
        if (keyString == null) {
            throw new IllegalArgumentException("Key string is null");
        }
        
        logger.fine("Processing public key starting with: " + 
                    (keyString.length() > 20 ? keyString.substring(0, 20) + "..." : keyString));
        
        List<Exception> errors = new ArrayList<>();
        
        // Method 1 (primary): Try as raw base64 encoded DER key directly - our standardized format
        try {
            byte[] decoded = Base64.getDecoder().decode(keyString);
            return (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(
                new X509EncodedKeySpec(decoded)
            );
        } catch (Exception e) {
            errors.add(new Exception("Raw DER format parsing failed: " + e.getMessage(), e));
        }
        
        // Method 2: Try as PEM formatted key (fallback for compatibility)
        try {
            if (keyString.contains("BEGIN PUBLIC KEY")) {
                String keyPart = keyString.replace("-----BEGIN PUBLIC KEY-----", "")
                                .replace("-----END PUBLIC KEY-----", "")
                                .replaceAll("\\s+", "");
                byte[] decoded = Base64.getDecoder().decode(keyPart);
                return (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(
                    new X509EncodedKeySpec(decoded)
                );
            }
        } catch (Exception e) {
            errors.add(new Exception("PEM format parsing failed: " + e.getMessage(), e));
        }
        
        // Method 3: Try with Python-style double encoding (fallback for compatibility)
        try {
            byte[] firstDecode = Base64.getDecoder().decode(keyString);
            byte[] secondDecode = Base64.getDecoder().decode(new String(firstDecode, StandardCharsets.UTF_8));
            return (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(
                new X509EncodedKeySpec(secondDecode)
            );
        } catch (Exception e) {
            errors.add(new Exception("Double-encoded key parsing failed: " + e.getMessage(), e));
        }
        
        // If all approaches failed, throw exception with details
        StringBuilder errorMsg = new StringBuilder("Failed to process public key. Attempted 3 methods.\n");
        for (int i = 0; i < errors.size(); i++) {
            errorMsg.append("Method ").append(i+1).append(" error: ")
                    .append(errors.get(i).getMessage()).append("\n");
        }
        logger.severe(errorMsg.toString());
        throw new Exception(errorMsg.toString());
    }

    public boolean requestConnection(String peerId) {
        if (!knownPeers.containsKey(peerId)) {
            logger.severe("Connection request failed: Peer " + peerId + " not found");
            return false;
        }
        Map<String, Object> peer = knownPeers.get(peerId);
        try (Socket s = new Socket((String) peer.get("host"), (Integer) peer.get("port"))) {
            s.setSoTimeout(5000);
            PrintWriter out = new PrintWriter(s.getOutputStream(), true);
            Map<String, Object> message = new HashMap<>();
            message.put("type", "connection_request");
            message.put("sender_id", userId);
            message.put("sender_name", username);
            message.put("sender_port", commPort);
            message.put("fingerprint", authManager.generateFingerprint());
            message.put("requires_mutual", true);
            out.println(gson.toJson(message));
            logger.info("Connection request sent to " + peerId);
            return true;
        } catch (Exception e) {
            logger.severe("Connection request failed to " + peerId + ": " + e.getMessage());
            return false;
        }
    }

    public boolean acceptConnection(String peerId, boolean verifyFingerprint) {
        Map<String, Object> request = pendingRequests.stream()
                .filter(r -> r.get("peer_id").equals(peerId))
                .findFirst()
                .orElse(null);
        if (request == null) {
            logger.severe("No pending request found for " + peerId);
            return false;
        }
        if (verifyFingerprint && request.get("fingerprint") != null) {
            if (!authManager.verifyPeer(peerId, (String) request.get("fingerprint"))) {
                logger.severe("Fingerprint verification failed for " + peerId);
                return false;
            }
        }
        pendingRequests.remove(request);
        Map<String, Object> peer = knownPeers.get(peerId);
        peer.put("connected", true);
        connectedPeers.put(peerId, peer);
        notifyConnectionStatusChanged.notify(peerId, true);
        try (Socket s = new Socket((String) peer.get("host"), (Integer) peer.get("port"))) {
            s.setSoTimeout(5000);
            PrintWriter out = new PrintWriter(s.getOutputStream(), true);
            Map<String, Object> message = new HashMap<>();
            message.put("type", "connection_response");
            message.put("peer_id", userId);
            message.put("accepted", true);
            message.put("sender_id", userId);
            message.put("sender_name", username);
            message.put("fingerprint", authManager.generateFingerprint());
            out.println(gson.toJson(message));
            logger.info("Sent connection acceptance to " + peerId);
            return true;
        } catch (Exception e) {
            logger.severe("Failed to send acceptance to " + peerId + ": " + e.getMessage());
            connectedPeers.remove(peerId);
            peer.put("connected", false);
            notifyConnectionStatusChanged.notify(peerId, false);
            return false;
        }
    }

    public boolean sendFile(String peerId, String fileName) {
        if (!connectedPeers.containsKey(peerId)) {
            logger.warning("Cannot send file to non-connected peer: " + peerId);
            return false;
        }
        Map<String, Object> peer = connectedPeers.get(peerId);
        if (peer == null) {
            logger.severe("Connected peer entry is null: " + peerId);
            return false;
        }
        notifyFileTransferStatus.notify(fileName, 0, "preparing", null);
        
        try (Socket s = new Socket((String) peer.get("host"), (Integer) peer.get("port"))) {
            s.setSoTimeout(60000); 
            
            // Generate ephemeral key pair for this exchange
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(new ECGenParameterSpec("secp384r1"));
            KeyPair kp = kpg.generateKeyPair();
            ECPrivateKey privateKey = (ECPrivateKey) kp.getPrivate();
            ECPublicKey publicKey = (ECPublicKey) kp.getPublic();
            
            // Create request
            Map<String, Object> request = new HashMap<>();
            request.put("type", "file_download_request");
            request.put("sender_id", userId);
            request.put("file_name", fileName);
            
            try {
                request.put("file_hash", getFileHash(fileName));
            } catch (Exception e) {
                logger.warning("Could not generate file hash: " + e.getMessage());
            }
            
            // Format public key in PEM format for Python compatibility
            String rawEncodedKey = Base64.getEncoder().encodeToString(publicKey.getEncoded());
            request.put("ephemeral_public", rawEncodedKey);
            
            // Send request
            PrintWriter out = new PrintWriter(s.getOutputStream(), true);
            out.println(gson.toJson(request));
            out.flush();
            
            // Read and parse response with retry logic
            BufferedReader in = new BufferedReader(new InputStreamReader(s.getInputStream()));
            int tries = 0;
            String responseText = null;
            while (responseText == null && tries < 5) {
                responseText = in.readLine();
                if (responseText == null) {
                    tries++;
                    logger.warning("Got empty response, retrying (" + tries + "/5)");
                    try {
                        Thread.sleep(100); 
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                }
            }
            
            if (responseText == null || responseText.isEmpty()) {
                throw new IOException("Empty response received after " + tries + " attempts");
            }
            
            Map<String, Object> response = gson.fromJson(responseText, new TypeToken<Map<String, Object>>(){}.getType());
            
            if (!"approved".equals(response.get("status"))) {
                logger.warning("File send rejected: " + response.getOrDefault("reason", "unknown"));
                notifyFileTransferStatus.notify(fileName, 0, "failed", "Peer denied request");
                return false;
            }
            
            // Process peer's public key using our utility method
            ECPublicKey peerPublic = processPublicKey((String) response.get("ephemeral_public"));
            
            // Generate shared key
            KeyAgreement ka = KeyAgreement.getInstance("ECDH");
            ka.init(privateKey);
            ka.doPhase(peerPublic, true);
            byte[] sharedKey = MessageDigest.getInstance("SHA-256").digest(ka.generateSecret());
            
            // Send the file
            sendFile(s, fileName, sharedKey);
            
            notifyFileTransferStatus.notify(fileName, 100, "completed", "");
            return true;
        } catch (Exception e) {
            logger.severe("Send file failed: " + e.getMessage());
            e.printStackTrace();
            notifyFileTransferStatus.notify(fileName, 0, "failed", e.getMessage());
            return false;
        }
    }

    private void encryptFile(String filePath, byte[] key) throws Exception {
        // Generate a random IV
        byte[] iv = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        
        // Create Cipher
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        
        // Read file, encrypt content
        File sourceFile = new File(filePath);
        byte[] fileContent = Files.readAllBytes(sourceFile.toPath());
        byte[] encryptedContent = cipher.doFinal(fileContent);
        
        // Write IV + encrypted content to temporary file
        File tempFile = new File(filePath + ".enc");
        try (FileOutputStream fos = new FileOutputStream(tempFile)) {
            fos.write(iv);  // First write IV
            fos.write(encryptedContent);  // Then write encrypted content
        }
        
        // Replace original file with encrypted version
        if (!tempFile.renameTo(sourceFile)) {
            Files.move(tempFile.toPath(), sourceFile.toPath(), 
                      java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private byte[] decryptFile(String filePath, byte[] key) throws Exception {
        File sourceFile = new File(filePath);
        byte[] fileContent = Files.readAllBytes(sourceFile.toPath());
        
        // File must have at least IV (16 bytes)
        if (fileContent.length <= 16) {
            throw new IllegalArgumentException("File too small to be valid encrypted content");
        }
        
        // Extract IV 
        byte[] iv = new byte[16];
        System.arraycopy(fileContent, 0, iv, 0, 16);
        
        // Extract encrypted content 
        byte[] encryptedContent = new byte[fileContent.length - 16];
        System.arraycopy(fileContent, 16, encryptedContent, 0, encryptedContent.length);
        
        // Setup decryption
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
        
        // Decrypt and return
        return cipher.doFinal(encryptedContent);
    }

    private boolean requestFileConsent(String peerId, String fileName) {
        logger.info("Consent requested for " + fileName + " from " + peerId);
        return true;
    }

    private void sendFile(Socket clientSocket, String fileName, byte[] key) throws Exception {
       
        clientSocket.setSoTimeout(60000); 
        
        // Get the file path and decrypt it with our local key
        String filePath = new File(sharedFilesDir, fileName).getAbsolutePath();
        byte[] localKey = MessageDigest.getInstance("SHA-256").digest(authManager.generateFingerprint().getBytes());
        byte[] decryptedData;
        
        try {
            decryptedData = decryptFile(filePath, localKey);
            logger.fine("Successfully decrypted " + fileName + " for sending");
        } catch (Exception e) {
            logger.severe("Failed to decrypt file for sending: " + e.getMessage());
            throw e;
        }
        
        // Create new IV and encrypt with shared key
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[16];
        random.nextBytes(iv);
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        byte[] encryptedData;
        
        try {
            encryptedData = cipher.doFinal(decryptedData);
            logger.fine("Successfully encrypted " + fileName + " with shared key");
        } catch (Exception e) {
            logger.severe("Failed to encrypt file with shared key: " + e.getMessage());
            throw e;
        }
        
        // Log details before sending
        logger.info("Sending file " + fileName + " - Encrypted size: " + encryptedData.length + 
                    " bytes, IV length: " + iv.length + " bytes");
        
        // Create a dedicated buffered output stream separate from any PrintWriter
        // already attached to the socket, to ensure binary data is written properly
        try (BufferedOutputStream out = new BufferedOutputStream(clientSocket.getOutputStream(), 16384)) {
            
            out.write(iv);
            out.flush();
            
            
            int chunkSize = 8192;
            for (int i = 0; i < encryptedData.length; i += chunkSize) {
                int length = Math.min(chunkSize, encryptedData.length - i);
                out.write(encryptedData, i, length);
                
               
                if (i % (chunkSize * 10) == 0) {
                    out.flush();
                }
            }
            
            
            out.flush();
            logger.info("Sent file " + fileName + " (" + encryptedData.length + " bytes) with IV");
        } catch (IOException e) {
            logger.severe("Error writing file data to socket: " + e.getMessage());
            throw e;
        }
    }

    private String getFileHash(String fileName) throws Exception {
        String filePath = new File(sharedFilesDir, fileName).getAbsolutePath();
        byte[] key = MessageDigest.getInstance("SHA-256").digest(authManager.generateFingerprint().getBytes());
        byte[] decryptedData = decryptFile(filePath, key);
        
        // Return hash as hexadecimal string to match Python implementation
        byte[] hashBytes = MessageDigest.getInstance("SHA-256").digest(decryptedData);
        StringBuilder hexString = new StringBuilder();
        for (byte b : hashBytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }

    public void notifyKeyChange() {
        String newFingerprint = authManager.generateFingerprint();
        logger.info("Generated new fingerprint: " + newFingerprint);
        if (connectedPeers.isEmpty()) {
            logger.warning("No connected peers to notify of key change");
            return;
        }
        for (Map.Entry<String, Map<String, Object>> entry : connectedPeers.entrySet()) {
            String peerId = entry.getKey();
            Map<String, Object> peer = entry.getValue();
            for (int attempt = 0; attempt < 3; attempt++) {
                try (Socket s = new Socket((String) peer.get("host"), (Integer) peer.get("port"))) {
                    s.setSoTimeout(10000);
                    PrintWriter out = new PrintWriter(s.getOutputStream(), true);
                    Map<String, Object> message = new HashMap<>();
                    message.put("type", "key_change_notification");
                    message.put("sender_id", userId);
                    message.put("sender_name", username);
                    message.put("new_fingerprint", newFingerprint);
                    out.println(gson.toJson(message));
                    logger.info("Notified " + peer.get("username") + " (" + peerId + ") of new fingerprint");
                    break;
                } catch (Exception e) {
                    logger.severe("Attempt " + (attempt + 1) + " failed to notify " + peerId + ": " + e.getMessage());
                    if (attempt == 2) logger.severe("Failed to notify " + peerId + " after 3 attempts");
                    try {
                        Thread.sleep(1000);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                    }
                }
            }
        }
    }

    public String addVerifiedPeer(String peerName, String fingerprint) {
        String peerId = UUID.randomUUID().toString();
        authManager.verifyPeer(peerId, fingerprint);
        Map<String, Object> peer = new HashMap<>();
        peer.put("username", peerName);
        peer.put("id", peerId);
        peer.put("fingerprint", fingerprint);
        peer.put("connected", false);
        knownPeers.put(peerId, peer);
        notifyPeerDiscovered.notify(peer);
        return peerId;
    }

    public void close() {
        running = false;
        try {
            jmdns.unregisterAllServices();
            jmdns.close();
            serverSocket.close();
        } catch (IOException e) {
            logger.severe("Error closing: " + e.getMessage());
        }
    }

    public AuthenticationManager getAuthManager() {
        return authManager;
    }

    public Map<String, Map<String, Object>> getKnownPeers() {
        return new HashMap<>(knownPeers);
    }
}