package isp.rsa;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

/**
 * Assuming Alice and Bob know each other's public key, secure the channel using a
 * RSA. Then exchange ten messages between Alice and Bob.
 *
 * (The remaining assignment(s) can be found in the isp.steganography.ImageSteganography
 * class.)
 */
public class A1AgentCommunicationRSA {
    public static void main(String[] args) throws Exception {

        // Create two public-secret key pairs
        final String algorithm = "RSA/ECB/OAEPPadding";
        final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        final KeyPair aliceKP = kpg.generateKeyPair();
        final KeyPair bobKP = kpg.generateKeyPair();

        final Environment env = new Environment();

        final String[] msgAlice = {"Whaddup bobby boi", "How are you today", "k byee",
                                    "k byeeee", "k byeeeee", "k byeeeeee", "k byeeeeeee",
                                    "k byeeeeeeee", "k beeeeeeeeeee", "k byeeeeeeeeeeeeeee"};

        final String[] msgBob = {"Whazzzzzup Alice", "Im terrible actually", "cya",
                                "cyaa", "cyaaa", "cyaaaa", "cyaaaaa", "cyaaaaaa", "cyaaaaaaaa", "cyaaaaaaaaaaaaa"};

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                for (int i = 0; i < 10; i++) {
                    final String message = msgAlice[i];
                    final byte[] pt = message.getBytes(StandardCharsets.UTF_8);

                    System.out.println("Message Alice: " + message);
                    System.out.println("PT Alice: " + Agent.hex(pt));

                    final Cipher rsaEnc = Cipher.getInstance(algorithm);
                    rsaEnc.init(Cipher.ENCRYPT_MODE, bobKP.getPublic());
                    final byte[] ct = rsaEnc.doFinal(pt);
                    System.out.println("CT Alice: " + Agent.hex(ct));

                    send("bob", ct);

                    // receive msg
                    final byte[] ctReceived = receive("bob");
                    System.out.println("CT received Alice: " + Agent.hex(ctReceived));
                    final Cipher rsaDec = Cipher.getInstance(algorithm);
                    rsaDec.init(Cipher.DECRYPT_MODE, aliceKP.getPrivate());
                    final byte[] decryptedText = rsaDec.doFinal(ctReceived);

                    System.out.println("PT received Alice: " + Agent.hex(decryptedText));
                    final String message2 = new String(decryptedText, StandardCharsets.UTF_8);
                    System.out.println("Message received Alice: " + message2);
                }

            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                for (int i = 0; i < 10; i++) {
                    // receive msg
                    final byte[] ctReceived = receive("alice");
                    System.out.println("CT received Bob: " + Agent.hex(ctReceived));
                    final Cipher rsaDec = Cipher.getInstance(algorithm);
                    rsaDec.init(Cipher.DECRYPT_MODE, bobKP.getPrivate());
                    final byte[] decryptedText = rsaDec.doFinal(ctReceived);

                    System.out.println("PT received Bob: " + Agent.hex(decryptedText));
                    final String message2 = new String(decryptedText, StandardCharsets.UTF_8);
                    System.out.println("Message received Bob: " + message2);

                    // send msg
                    final String message = msgBob[i];
                    final byte[] pt = message.getBytes(StandardCharsets.UTF_8);

                    System.out.println("Message Bob: " + message);
                    System.out.println("PT Bob: " + Agent.hex(pt));

                    final Cipher rsaEnc = Cipher.getInstance(algorithm);
                    rsaEnc.init(Cipher.ENCRYPT_MODE, aliceKP.getPublic());
                    final byte[] ct = rsaEnc.doFinal(pt);
                    System.out.println("CT Bob: " + Agent.hex(ct));

                    send("alice", ct);
                }
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}