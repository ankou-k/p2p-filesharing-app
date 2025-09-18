import com.google.gson.Gson;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.io.File;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

public class SecureP2PFileShareGUI extends JFrame {
    private String username;
    private SecureP2PFileSharing p2pClient;
    private Logger logger;
    private JList<String> peersList;
    private DefaultListModel<String> peersListModel;
    private JTable contactsTable;
    private JTable sharedFilesTable;
    private JTable receivedFilesTable;
    private String selectedPeer;
    private Gson gson = new Gson();

    public SecureP2PFileShareGUI(String username, int port) throws Exception {
        this.username = username != null ? username : "User_" + ProcessHandle.current().pid();
        this.p2pClient = new SecureP2PFileSharing(this.username, port, null);
        this.logger = Logger.getLogger("GUI-" + this.username);
        initUI();
        setupSignals();
        new Thread(this::updatePeersLoop, "PeerUpdateThread").start();
    }

    private void initUI() {
        setTitle("Secure P2P File Sharing - " + username);
        setSize(800, 600);
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setLocation(100, 100);

        JPanel mainPanel = new JPanel(new BorderLayout());

        JPanel leftPanel = new JPanel(new BorderLayout());
        leftPanel.setPreferredSize(new Dimension(250, 600));

        peersListModel = new DefaultListModel<>();
        peersList = new JList<>(peersListModel);
        peersList.addListSelectionListener(e -> peerSelected(peersList.getSelectedValue()));
        leftPanel.add(new JLabel("Discovered Peers"), BorderLayout.NORTH);
        leftPanel.add(new JScrollPane(peersList), BorderLayout.CENTER);

        contactsTable = new JTable(new DefaultTableModel(new Object[0][3], new String[]{"Name", "Fingerprint", "Action"}));
        contactsTable.setPreferredScrollableViewportSize(new Dimension(250, 100));
        leftPanel.add(new JLabel("Verified Contacts"), BorderLayout.SOUTH);
        leftPanel.add(new JScrollPane(contactsTable), BorderLayout.SOUTH);

        JPanel rightPanel = new JPanel(new BorderLayout());

        JPanel rightInnerPanel = new JPanel(new BorderLayout());
        sharedFilesTable = new JTable(new DefaultTableModel(new Object[0][3], new String[]{"Name", "Size", "Hash"}));
        rightInnerPanel.add(new JLabel("Shared Files"), BorderLayout.NORTH);
        rightInnerPanel.add(new JScrollPane(sharedFilesTable), BorderLayout.CENTER);

        JPanel shareSendPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton shareFileBtn = new JButton("Share New File");
        shareFileBtn.addActionListener(e -> shareFile());
        shareSendPanel.add(shareFileBtn);

        JButton sendFileBtn = new JButton("Send File");
        sendFileBtn.addActionListener(e -> sendFileDialog());
        shareSendPanel.add(sendFileBtn);
        rightInnerPanel.add(shareSendPanel, BorderLayout.SOUTH);

        rightPanel.add(rightInnerPanel, BorderLayout.CENTER);

        receivedFilesTable = new JTable(new DefaultTableModel(new Object[0][4], new String[]{"Name", "Size", "Hash", "Action"}));
        receivedFilesTable.setPreferredScrollableViewportSize(new Dimension(500, 100));
        rightPanel.add(new JLabel("Received Files"), BorderLayout.SOUTH);
        rightPanel.add(new JScrollPane(receivedFilesTable), BorderLayout.SOUTH);

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton connectBtn = new JButton("Connect to Peer");
        connectBtn.addActionListener(e -> connectToPeer());
        buttonPanel.add(connectBtn);

        JButton viewFilesBtn = new JButton("View Peer Files");
        viewFilesBtn.addActionListener(e -> viewPeerFiles());
        buttonPanel.add(viewFilesBtn);

        JButton addContactBtn = new JButton("Add Contact");
        addContactBtn.addActionListener(e -> addContactDialog());
        buttonPanel.add(addContactBtn);

        JButton rotateKeysBtn = new JButton("Rotate Keys");
        rotateKeysBtn.addActionListener(e -> rotateKeysDialog());
        buttonPanel.add(rotateKeysBtn);

        rightPanel.add(buttonPanel, BorderLayout.NORTH);

        mainPanel.add(leftPanel, BorderLayout.WEST);
        mainPanel.add(rightPanel, BorderLayout.CENTER);
        setContentPane(mainPanel);

        refreshSharedFilesList();
        refreshContactsList();
    }

    private void setupSignals() {
        p2pClient.notifyConnectionRequest = request -> SwingUtilities.invokeLater(() -> handleConnectionRequest(request));
        p2pClient.notifyConnectionStatusChanged = (peerId, connected) -> SwingUtilities.invokeLater(() -> handleConnectionStatusChanged(peerId, connected));
        p2pClient.notifyFileTransferStatus = (fileName, progress, status, errorMsg) -> SwingUtilities.invokeLater(() -> handleFileTransferStatus(fileName, progress, status, errorMsg));
        p2pClient.notifyPeerDiscovered = peer -> SwingUtilities.invokeLater(this::updatePeersList);
    }

    private void updatePeersLoop() {
        while (true) {
            updatePeersList();
            try {
                Thread.sleep(2000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }

    private void updatePeersList() {
        List<Map<String, Object>> peers = p2pClient.getDiscoveredPeers();
        peersListModel.clear();
        for (Map<String, Object> peer : peers) {
            String peerId = (String) peer.get("id");
            String username = (String) peer.get("username");
            
            // If username is null but ID contains username info, extract it
            if ((username == null || username.trim().isEmpty()) && peerId != null && peerId.contains("username=")) {
                try {
                    int usernameStart = peerId.indexOf("username=") + 9;
                    int usernameEnd = peerId.length();
                    if (peerId.indexOf(",", usernameStart) > 0) {
                        usernameEnd = peerId.indexOf(",", usernameStart);
                    }
                    username = peerId.substring(usernameStart, usernameEnd);
                } catch (Exception e) {
                    logger.warning("Failed to extract username from ID: " + peerId);
                }
            }
            
            // Still use fallback if needed
            if (username == null || username.trim().isEmpty()) {
                username = "Unknown_" + (peerId != null ? peerId.substring(0, Math.min(8, peerId.length())) : "unknown");
            }
            
            String display = username + " " + (Boolean.TRUE.equals(peer.get("connected")) ? "(Connected)" : "(Discovered)");
            if (!peersListModel.contains(display)) {
                peersListModel.addElement(display);
            }
        }
    }

    private void handleConnectionRequest(Map<String, Object> request) {
        String peerId = (String) request.get("peer_id");
        String peerName = (String) request.get("peer_name");
        String fingerprint = (String) request.getOrDefault("fingerprint", "Unknown");
        int reply = JOptionPane.showConfirmDialog(this,
                peerName + " (" + peerId + ") wants to connect.\nFingerprint: " + fingerprint + "\nAccept?",
                "Connection Request", JOptionPane.YES_NO_OPTION);
        if (reply == JOptionPane.YES_OPTION) {
            p2pClient.acceptConnection(peerId, true);
            updatePeersList();
        }
    }

    private void handleConnectionStatusChanged(String peerId, boolean connected) {
        logger.info("Connection status changed: peerId=" + peerId + ", connected=" + connected);
        Map<String, Object> peer = p2pClient.getKnownPeers().get(peerId);
        if (peer != null) {
            peer.put("connected", connected);
            updatePeersList();
        }
    }

    private void handleFileTransferStatus(String fileName, int progress, String status, String errorMsg) {
        if ("completed".equals(status)) {
            JOptionPane.showMessageDialog(this, "File " + fileName + " transfer completed!", "File Transfer", JOptionPane.INFORMATION_MESSAGE);
            refreshSharedFilesList();
            if (selectedPeer != null) viewPeerFiles();
        } else if ("failed".equals(status)) {
            String message = "File " + fileName + " transfer failed!" + (errorMsg.isEmpty() ? "" : "\nError: " + errorMsg);
            JOptionPane.showMessageDialog(this, message, "File Transfer", JOptionPane.WARNING_MESSAGE);
        }
    }

    private void peerSelected(String peer) {
        if (peer != null && !peer.trim().isEmpty()) {
            this.selectedPeer = peer.split(" ")[0];
            logger.info("Selected peer: " + selectedPeer);
        } else {
            this.selectedPeer = null;
        }
    }

    private void connectToPeer() {
        if (selectedPeer == null || selectedPeer.trim().isEmpty()) {
            JOptionPane.showMessageDialog(this, "No peer selected", "Error", JOptionPane.WARNING_MESSAGE);
            return;
        }
        String peerId = p2pClient.getDiscoveredPeers().stream()
                .filter(p -> {
                    String username = (String) p.get("username");
                    return username != null && username.equals(selectedPeer);
                })
                .findFirst()
                .map(p -> (String) p.get("id"))
                .orElse(null);
        if (peerId != null && p2pClient.requestConnection(peerId)) {
            JOptionPane.showMessageDialog(this, "Connection request sent to " + selectedPeer, "Connection", JOptionPane.INFORMATION_MESSAGE);
        } else {
            JOptionPane.showMessageDialog(this, "Failed to send connection request to " + selectedPeer, "Error", JOptionPane.WARNING_MESSAGE);
            logger.warning("Peer ID not found or connection request failed for: " + selectedPeer);
        }
    }

    private void viewPeerFiles() {
        if (selectedPeer != null) {
            String peerId = p2pClient.getDiscoveredPeers().stream()
                    .filter(p -> {
                        String username = (String) p.get("username");
                        return username != null && username.equals(selectedPeer);
                    })
                    .findFirst()
                    .map(p -> (String) p.get("id"))
                    .orElse(null);
            if (peerId != null) {
                List<Map<String, Object>> files = p2pClient.getFilesFromPeer(peerId, null);
                DefaultTableModel model = new DefaultTableModel(new Object[0][4], new String[]{"Name", "Size", "Hash", "Action"}) {
                    @Override
                    public boolean isCellEditable(int row, int column) {
                        return column == 3;
                    }
                };
                for (Map<String, Object> file : files) {
                    model.addRow(new Object[]{file.get("name"), file.get("size"), file.get("hash"), "Download"});
                }
                receivedFilesTable.setModel(model);
                receivedFilesTable.getColumn("Action").setCellRenderer(new ButtonRenderer());
                receivedFilesTable.getColumn("Action").setCellEditor(new ButtonEditor(new JCheckBox(), peerId));
            }
        }
    }

    private void addContactDialog() {
        String name = JOptionPane.showInputDialog(this, "Enter peer name:");
        if (name != null) {
            String fingerprint = JOptionPane.showInputDialog(this, "Enter peer fingerprint:");
            if (fingerprint != null) {
                p2pClient.addVerifiedPeer(name, fingerprint);
                refreshContactsList();
            }
        }
    }

    private void shareFile() {
        JFileChooser fileChooser = new JFileChooser();
        if (fileChooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            String filePath = fileChooser.getSelectedFile().getAbsolutePath();
            try {
                if (p2pClient.addSharedFile(filePath)) {
                    refreshSharedFilesList();
                    JOptionPane.showMessageDialog(this, "File " + new File(filePath).getName() + " is now shared", "File Shared", JOptionPane.INFORMATION_MESSAGE);
                } else {
                    JOptionPane.showMessageDialog(this, "Failed to share file", "Error", JOptionPane.WARNING_MESSAGE);
                }
            } catch (Exception e) {
                JOptionPane.showMessageDialog(this, "Error sharing file: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void sendFileDialog() {
        if (selectedPeer != null) {
            String peerId = p2pClient.getDiscoveredPeers().stream()
                    .filter(p -> {
                        String username = (String) p.get("username");
                        return username != null && username.equals(selectedPeer);
                    })
                    .findFirst()
                    .map(p -> (String) p.get("id"))
                    .orElse(null);
            if (peerId != null) {
                JFileChooser fileChooser = new JFileChooser();
                if (fileChooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
                    String fileName = fileChooser.getSelectedFile().getName();
                    if (p2pClient.sendFile(peerId, fileName)) {
                        JOptionPane.showMessageDialog(this, "File " + fileName + " sent successfully", "File Sent", JOptionPane.INFORMATION_MESSAGE);
                    } else {
                        JOptionPane.showMessageDialog(this, "Failed to send file", "Error", JOptionPane.WARNING_MESSAGE);
                    }
                }
            }
        }
    }

    private void refreshSharedFilesList() {
        List<Map<String, Object>> files = p2pClient.listSharedFiles();
        DefaultTableModel model = new DefaultTableModel(new Object[0][3], new String[]{"Name", "Size", "Hash"});
        for (Map<String, Object> file : files) {
            model.addRow(new Object[]{file.get("name"), file.get("size"), file.get("hash")});
        }
        sharedFilesTable.setModel(model);
    }

    private void refreshContactsList() {
        DefaultTableModel model = new DefaultTableModel(new Object[0][3], new String[]{"Name", "Fingerprint", "Action"});
        for (Map.Entry<String, Map<String, String>> entry : p2pClient.getAuthManager().getVerifiedPeers().entrySet()) {
            String peerId = entry.getKey();
            Map<String, String> peerInfo = entry.getValue();
            Object usernameObj = p2pClient.getKnownPeers().getOrDefault(peerId, new HashMap<>()).getOrDefault("username", "Unknown");
            String peerName = (usernameObj != null) ? usernameObj.toString() : "Unknown";
            model.addRow(new Object[]{peerName, peerInfo.get("fingerprint"), "Remove"});
        }
        contactsTable.setModel(model);
    }

    private void downloadFile(Map<String, Object> fileInfo, String peerId) {
        if (fileInfo == null || peerId == null) {
            JOptionPane.showMessageDialog(this, "Invalid file or peer information", "Error", JOptionPane.WARNING_MESSAGE);
            return;
        }
        int reply = JOptionPane.showConfirmDialog(this,
                "Download " + fileInfo.get("name") + " from " + selectedPeer + "?",
                "Download File", JOptionPane.YES_NO_OPTION);
        if (reply == JOptionPane.YES_OPTION) {
            boolean success = p2pClient.requestFileDownload(peerId, (String) fileInfo.get("name"), (String) fileInfo.get("hash"));
            if (success) {
                JOptionPane.showMessageDialog(this, "Download of " + fileInfo.get("name") + " has started", "Download Started", JOptionPane.INFORMATION_MESSAGE);
            } else {
                JOptionPane.showMessageDialog(this, "Failed to start download of " + fileInfo.get("name"), "Download Failed", JOptionPane.WARNING_MESSAGE);
            }
        }
    }

    private void rotateKeysDialog() {
        String password = JOptionPane.showInputDialog(this, "Enter master password:");
        if (password != null) {
            String[] result = p2pClient.getAuthManager().rotateKeys(password);
            if (Boolean.parseBoolean(result[0])) {
                p2pClient.notifyKeyChange();
                JOptionPane.showMessageDialog(this, "New fingerprint: " + result[1], "Keys Rotated", JOptionPane.INFORMATION_MESSAGE);
            } else {
                JOptionPane.showMessageDialog(this, "Key rotation failed", "Error", JOptionPane.WARNING_MESSAGE);
            }
        }
    }

    @Override
    public void dispose() {
        p2pClient.close();
        super.dispose();
    }

    class ButtonRenderer extends JButton implements javax.swing.table.TableCellRenderer {
        public ButtonRenderer() {
            setOpaque(true);
        }

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
            setText((value == null) ? "" : value.toString());
            return this;
        }
    }

    class ButtonEditor extends DefaultCellEditor {
        private JButton button;
        private String peerId;
        private int row;

        public ButtonEditor(JCheckBox checkBox, String peerId) {
            super(checkBox);
            this.peerId = peerId;
            button = new JButton();
            button.setOpaque(true);
            button.addActionListener(e -> {
                Map<String, Object> fileInfo = new HashMap<>();
                fileInfo.put("name", receivedFilesTable.getValueAt(row, 0));
                fileInfo.put("size", receivedFilesTable.getValueAt(row, 1));
                fileInfo.put("hash", receivedFilesTable.getValueAt(row, 2));
                downloadFile(fileInfo, peerId);
            });
        }

        @Override
        public Component getTableCellEditorComponent(JTable table, Object value, boolean isSelected, int row, int column) {
            this.row = row;
            button.setText((value == null) ? "" : value.toString());
            return button;
        }

        @Override
        public Object getCellEditorValue() {
            return button.getText();
        }
    }

    public static void main(String[] args) {
        // Parse command-line arguments
        String username = null;
        int port = 0;
        
        try {
            // Check for username
            if (args.length > 0) {
                username = args[0];
            }
            
            // Check for port
            if (args.length > 1) {
                port = Integer.parseInt(args[1]);
            }
            
            // Information about current configuration
            System.out.println("Starting P2P client with:");
            System.out.println("Username: " + (username != null ? username : "Auto-generated"));
            System.out.println("Port: " + (port != 0 ? port : "Auto-assigned"));
            
            // Launch the application
            final String finalUsername = username;
            final int finalPort = port;
            
            SwingUtilities.invokeLater(() -> {
                try {
                    SecureP2PFileShareGUI gui = new SecureP2PFileShareGUI(finalUsername, finalPort);
                    gui.setVisible(true);
                } catch (Exception e) {
                    System.err.println("Failed to start application: " + e.getMessage());
                    e.printStackTrace();
                }
            });
        } catch (NumberFormatException e) {
            System.err.println("Error: Port must be a valid number");
            System.err.println("Usage: java -cp \"classes;libs/*\" SecureP2PFileShareGUI [username] [port]");
            System.exit(1);
        }
    }
}