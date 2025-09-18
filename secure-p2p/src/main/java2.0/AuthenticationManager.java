import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

public class AuthenticationManager {
    private String username;
    private String keysPath;
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private Map<String, Map<String, String>> verifiedPeers;
    private Logger logger;
    private Gson gson = new Gson();

    public AuthenticationManager(String username, String keysPath) {
        this.username = username;
        this.keysPath = keysPath;
        this.verifiedPeers = new HashMap<>();
        this.logger = Logger.getLogger("AuthManager-" + username);
        loadOrCreateKeys(null);
    }

    private void loadOrCreateKeys(String masterPassword) {
        File keyFile = new File(keysPath, username + "_keys.json");
        new File(keysPath).mkdirs();

        if (keyFile.exists()) {
            try (FileReader reader = new FileReader(keyFile)) {
                Map<String, Object> fileData = gson.fromJson(reader, new TypeToken<Map<String, Object>>(){}.getType());
                boolean encrypted = (Boolean) fileData.getOrDefault("encrypted", false);
                if (encrypted) {
                    if (masterPassword == null) throw new IllegalArgumentException("Master password required");
                    String decryptedData = decryptData(Base64.getDecoder().decode((String) fileData.get("data")), masterPassword);
                    Map<String, Object> keyData = gson.fromJson(decryptedData, new TypeToken<Map<String, Object>>(){}.getType());
                    loadKeysFromData(keyData);
                } else {
                    loadKeysFromData((Map<String, Object>) fileData.get("data"));
                }
            } catch (Exception e) {
                logger.severe("Error loading keys: " + e.getMessage());
            }
        } else {
            try {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                kpg.initialize(2048);
                KeyPair kp = kpg.generateKeyPair();
                this.privateKey = kp.getPrivate();
                this.publicKey = kp.getPublic();
                saveKeys(null);
            } catch (NoSuchAlgorithmException e) {
                logger.severe("Key generation failed: " + e.getMessage());
            }
        }
    }

    private void loadKeysFromData(Map<String, Object> keyData) throws Exception {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        this.privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode((String) keyData.get("private_key"))));
        this.publicKey = kf.generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode((String) keyData.get("public_key"))));
        this.verifiedPeers = (Map<String, Map<String, String>>) keyData.getOrDefault("verified_peers", new HashMap<>());
    }

    private String encryptData(byte[] data, String password) throws Exception {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        SecretKeySpec key = deriveKey(password, salt);
        byte[] iv = new byte[16];
        random.nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] ciphertext = cipher.doFinal(data);
        byte[] result = new byte[salt.length + iv.length + ciphertext.length];
        System.arraycopy(salt, 0, result, 0, salt.length);
        System.arraycopy(iv, 0, result, salt.length, iv.length);
        System.arraycopy(ciphertext, 0, result, salt.length + iv.length, ciphertext.length);
        return Base64.getEncoder().encodeToString(result);
    }

    private String decryptData(byte[] encryptedData, String password) throws Exception {
        byte[] salt = new byte[16];
        byte[] iv = new byte[16];
        byte[] ciphertext = new byte[encryptedData.length - 32];
        System.arraycopy(encryptedData, 0, salt, 0, 16);
        System.arraycopy(encryptedData, 16, iv, 0, 16);
        System.arraycopy(encryptedData, 32, ciphertext, 0, ciphertext.length);
        SecretKeySpec key = deriveKey(password, salt);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] decrypted = cipher.doFinal(ciphertext);
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    private SecretKeySpec deriveKey(String password, byte[] salt) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(password.getBytes(StandardCharsets.UTF_8));
        md.update(salt);
        byte[] key = md.digest();
        return new SecretKeySpec(key, "AES");
    }

    private void saveKeys(String masterPassword) {
        File keyFile = new File(keysPath, username + "_keys.json");
        Map<String, Object> keyData = new HashMap<>();
        keyData.put("private_key", Base64.getEncoder().encodeToString(privateKey.getEncoded()));
        keyData.put("public_key", Base64.getEncoder().encodeToString(publicKey.getEncoded()));
        keyData.put("verified_peers", verifiedPeers);
        try {
            Map<String, Object> fileData = new HashMap<>();
            if (masterPassword != null) {
                String encryptedData = encryptData(gson.toJson(keyData).getBytes(StandardCharsets.UTF_8), masterPassword);
                fileData.put("encrypted", true);
                fileData.put("data", encryptedData);
            } else {
                fileData.put("encrypted", false);
                fileData.put("data", keyData);
            }
            try (FileWriter writer = new FileWriter(keyFile)) {
                gson.toJson(fileData, writer);
            }
        } catch (Exception e) {
            logger.severe("Error saving keys: " + e.getMessage());
        }
    }

    public String generateFingerprint() {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] publicKeyBytes = publicKey.getEncoded();
            return Base64.getEncoder().encodeToString(md.digest(publicKeyBytes)).substring(0, 16);
        } catch (NoSuchAlgorithmException e) {
            logger.severe("Fingerprint generation failed: " + e.getMessage());
            return "";
        }
    }

    public boolean verifyPeer(String peerId, String peerFingerprint) {
        for (Map.Entry<String, Map<String, String>> entry : verifiedPeers.entrySet()) {
            if (entry.getValue().get("fingerprint").equals(peerFingerprint) && !entry.getKey().equals(peerId)) {
                entry.getValue().put("verified_at", java.time.Instant.now().toString());
                saveKeys(null);
                return true;
            }
        }
        Map<String, String> peerInfo = new HashMap<>();
        peerInfo.put("fingerprint", peerFingerprint);
        peerInfo.put("verified_at", java.time.Instant.now().toString());
        verifiedPeers.put(peerId, peerInfo);
        saveKeys(null);
        return true;
    }

    public boolean isPeerVerified(String peerId) {
        return verifiedPeers.containsKey(peerId);
    }

    public String[] rotateKeys(String masterPassword) {
        PrivateKey oldPrivateKey = this.privateKey; 
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair kp = kpg.generateKeyPair();
            this.privateKey = kp.getPrivate();
            this.publicKey = kp.getPublic();
            String newFingerprint = generateFingerprint();
            saveKeys(masterPassword);
            logger.info("Keys rotated successfully, new fingerprint: " + newFingerprint);
            return new String[]{String.valueOf(true), newFingerprint};
        } catch (Exception e) {
            this.privateKey = oldPrivateKey;
            logger.severe("Key rotation failed: " + e.getMessage());
            return new String[]{String.valueOf(false), ""};
        }
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    // Added getter for GUI access
    public Map<String, Map<String, String>> getVerifiedPeers() {
        return new HashMap<>(verifiedPeers); // Return a copy to prevent external modification
    }
}