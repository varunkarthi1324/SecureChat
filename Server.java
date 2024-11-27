import java.io.*;
import java.net.*;
import java.security.*;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

public class Server {
    private static final int PORT = 12345;

    public static void main(String[] args) throws Exception {
        ServerSocket serverSocket = new ServerSocket(PORT);
        System.out.println("Server started...");

        Socket clientSocket = serverSocket.accept();
        System.out.println("Client connected...");

        BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
        PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);

        // Key exchange
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair pair = keyGen.generateKeyPair();
        PublicKey publicKey = pair.getPublic();
        PrivateKey privateKey = pair.getPrivate();

        // Send public key to client
        out.println(Base64.getEncoder().encodeToString(publicKey.getEncoded()));

        // Receive AES key from client
        String encryptedAesKey = in.readLine();
        Cipher rsaCipher = Cipher.getInstance("RSA");
        rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] aesKeyBytes = rsaCipher.doFinal(Base64.getDecoder().decode(encryptedAesKey));
        SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");

        // Communication
        Cipher aesCipher = Cipher.getInstance("AES");
        while (true) {
            String encryptedMessage = in.readLine();
            aesCipher.init(Cipher.DECRYPT_MODE, aesKey);
            byte[] decryptedMessageBytes = aesCipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
            String decryptedMessage = new String(decryptedMessageBytes);
            System.out.println("Decrypted Message: " + decryptedMessage); // Debug statement

            if (decryptedMessage.equalsIgnoreCase("exit")) {
                System.out.println("Client requested to exit. Closing connection...");
                break;
            }

            System.out.println("Client: " + decryptedMessage);
            
            System.out.print("Server: ");
            String response = new BufferedReader(new InputStreamReader(System.in)).readLine();

            if (response.equalsIgnoreCase("exit")) {
                System.out.println("Server requested to exit. Closing connection...");
                aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);
                byte[] encryptedResponseBytes = aesCipher.doFinal("exit".getBytes());
                String encryptedResponse = Base64.getEncoder().encodeToString(encryptedResponseBytes);
                out.println(encryptedResponse);
                break;
            }

            aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);
            byte[] encryptedResponseBytes = aesCipher.doFinal(response.getBytes());
            String encryptedResponse = Base64.getEncoder().encodeToString(encryptedResponseBytes);
            System.out.println("Encrypted Response: " + encryptedResponse); // Debug statement
            out.println(encryptedResponse);
        }

        clientSocket.close();
        serverSocket.close();
        System.out.println("Server stopped.");
    }
}
