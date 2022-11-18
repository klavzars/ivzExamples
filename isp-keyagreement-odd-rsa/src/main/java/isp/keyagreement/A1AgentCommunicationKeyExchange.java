package isp.keyagreement;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;

/*
 * Implement a key exchange between Alice and Bob using public-key encryption.
 * Once the shared secret is established, send an encrypted message from Alice to Bob using
 * AES in GCM.
 */
public class A1AgentCommunicationKeyExchange {
    public static void main(String[] args) throws Exception {
        // Create two public-secret key pairs
        final String algorithm = "RSA/ECB/OAEPPadding";
        final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        final KeyPair aliceKP = kpg.generateKeyPair();
        final KeyPair bobKP = kpg.generateKeyPair();
        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {

            // alice sends public key
            final byte[] alicePK = aliceKP.getPublic().getEncoded();
            send("bob", alicePK);

            // alice receives encrypted key, decrypts it
            final byte[] ctReceived = receive("bob");
            System.out.println("CT KEY received Alice: " + Agent.hex(ctReceived));
            final Cipher rsaDec = Cipher.getInstance(algorithm);
            rsaDec.init(Cipher.DECRYPT_MODE, aliceKP.getPrivate());
            final byte[] decryptedKey = rsaDec.doFinal(ctReceived);

            System.out.println("KEY received Alice: " + Agent.hex(decryptedKey));

            // encrypts pt with aes and sends it
            final String text = "Whazaaaah";
            final byte[] pt = text.getBytes(StandardCharsets.UTF_8);
            final Cipher alice = Cipher.getInstance("AES/GCM/NoPadding");
            alice.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(decryptedKey, "AES"));
            final byte[] ct = alice.doFinal(pt);
            System.out.printf("CT ALICE:  %s%n", Agent.hex(ct));
            final byte[] iv = alice.getIV();
            System.out.printf("IV ALICE:  %s%n", Agent.hex(iv));

            send("bob", ct);
            send("bob", iv);


            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {

            // bob receives public key
            X509EncodedKeySpec alicePKSpec = new X509EncodedKeySpec(receive("alice"));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey alicePK = keyFactory.generatePublic(alicePKSpec);

            //bob creates aes key
            final Key key = KeyGenerator.getInstance("AES").generateKey();
            final byte[] aesKey = key.getEncoded();
            System.out.println("KEY generated Bob: " + Agent.hex(aesKey));

            // encrypts and sends key
            final Cipher rsaEnc = Cipher.getInstance(algorithm);
            rsaEnc.init(Cipher.ENCRYPT_MODE, alicePK);
            final byte[] ctKey = rsaEnc.doFinal(aesKey);
            send("alice", ctKey);

            // receiving msg
            final byte[] ctReceived = receive("alice");
            final byte[] ivReceived = receive("alice");
            System.out.printf("CT RECEIVED BOB:  %s%n", Agent.hex(ctReceived));
            System.out.printf("IV RECEIVED BOB: %s%n", Agent.hex(ivReceived));

            // decrypt
            final Cipher bob = Cipher.getInstance("AES/GCM/NoPadding") ;
            final GCMParameterSpec specs = new GCMParameterSpec(128, ivReceived);
            bob.init(Cipher.DECRYPT_MODE, key, specs);
            final byte[] ptReceived = bob.doFinal(ctReceived);
            System.out.printf("PT RECEIVED BOB:  %s%n", Agent.hex(ptReceived));
            System.out.printf("MSG RECEIVED BOB: %s%n", new String(ptReceived, StandardCharsets.UTF_8));
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}