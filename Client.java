import java.io.*;
import java.net.*;
import java.security.*;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class Client {
    private static final String SERVER_ADDRESS = "localhost";
    private static final int PORT = 12345;

    public static void main(String[] args) throws Exception {
        Socket socket = new Socket(SERVER_ADDRESS, PORT);
        System.out.println("Connected to server...");

        BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        PrintWriter out = new PrintWriter(socket.getOutputStream(), true);

        // Key exchange
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair pair = keyGen.generateKeyPair();
        PublicKey publicKey = pair.getPublic();
        PrivateKey privateKey = pair.getPrivate();

        // Receive public key from server
        String serverPublicKeyStr = in.readLine();
        byte[] serverPublicKeyBytes = Base64.getDecoder().decode(serverPublicKeyStr);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey serverPublicKey = keyFactory.generatePublic(new X509EncodedKeySpec(serverPublicKeyBytes));

        // Generate AES key
        KeyGenerator aesKeyGen = KeyGenerator.getInstance("AES");
        aesKeyGen.init(128);
        SecretKey aesKey = aesKeyGen.generateKey();

        // Encrypt AES key with server's public key
        Cipher rsaCipher = Cipher.getInstance("RSA");
        rsaCipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
        byte[] encryptedAesKey = rsaCipher.doFinal(aesKey.getEncoded());
        out.println(Base64.getEncoder().encodeToString(encryptedAesKey));

        // Communication
        Cipher aesCipher = Cipher.getInstance("AES");
        while (true) {
            System.out.print("Client: ");
            String message = new BufferedReader(new InputStreamReader(System.in)).readLine();

            aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);
            byte[] encryptedMessageBytes = aesCipher.doFinal(message.getBytes());
            String encryptedMessage = Base64.getEncoder().encodeToString(encryptedMessageBytes);
            System.out.println("Encrypted Message: " + encryptedMessage); // Debug statement
            out.println(encryptedMessage);

            if (message.equalsIgnoreCase("exit")) {
                System.out.println("Client requested to exit. Closing connection...");
                break;
            }

            String encryptedResponse = in.readLine();
            aesCipher.init(Cipher.DECRYPT_MODE, aesKey);
            byte[] decryptedResponseBytes = aesCipher.doFinal(Base64.getDecoder().decode(encryptedResponse));
            String decryptedResponse = new String(decryptedResponseBytes);
            System.out.println("Decrypted Response: " + decryptedResponse); // Debug statement

            if (decryptedResponse.equalsIgnoreCase("exit")) {
                System.out.println("Server requested to exit. Closing connection...");
                break;
            }

            System.out.println("Server: " + decryptedResponse);
        }

        socket.close();
        System.out.println("Client stopped.");
    }
}
