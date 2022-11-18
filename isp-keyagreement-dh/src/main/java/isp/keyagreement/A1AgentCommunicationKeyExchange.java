package isp.keyagreement;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
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
        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {

            // alice sends public key
            final KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
            kpg.initialize(2048);
            final KeyPair aliceKP = kpg.generateKeyPair();
            final byte[] alicePK = aliceKP.getPublic().getEncoded();
            send("bob", alicePK);

            // alice receives bob's pk
            final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(receive("bob"));
            final DHPublicKey bobPK = (DHPublicKey) KeyFactory.getInstance("DH").generatePublic(keySpec);
            final KeyAgreement dh = KeyAgreement.getInstance("DH");
            dh.init(aliceKP.getPrivate());
            dh.doPhase(bobPK, true);

            //shared aes key
            final byte[] sharedSecret = dh.generateSecret();
            print("Shared secret: g^ab = B^a = %s", hex(sharedSecret));
            // By default, the shared secret will be 32 bytes long, but our cipher requires keys of length 16 bytes
            final SecretKeySpec aesKey = new SecretKeySpec(sharedSecret, 0, 16, "AES");

            // encrypts pt with aes and sends it
            final String text = "Whazaaaah";
            final byte[] pt = text.getBytes(StandardCharsets.UTF_8);
            final Cipher alice = Cipher.getInstance("AES/GCM/NoPadding");
            alice.init(Cipher.ENCRYPT_MODE, aesKey);
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
            final DHPublicKey alicePK = (DHPublicKey) KeyFactory.getInstance("DH").generatePublic(alicePKSpec);
            final DHParameterSpec dhParamSpec = alicePK.getParams();

            //bob creates dh key pair
            final KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
            kpg.initialize(dhParamSpec);
            final KeyPair keyPair = kpg.generateKeyPair();
            send("alice", keyPair.getPublic().getEncoded());
            print("  My contribution: B = g^b = %s", hex(keyPair.getPublic().getEncoded()));

            final KeyAgreement dh = KeyAgreement.getInstance("DH");
            dh.init(keyPair.getPrivate());
            dh.doPhase(alicePK, true);

            // shared aes key
            final byte[] sharedSecret = dh.generateSecret();
            print("  Shared secret: g^ab = A^b = %s", hex(sharedSecret));
            // By default, the shared secret will be 32 bytes long, but our cipher requires keys of length 16 bytes
            final SecretKeySpec aesKey = new SecretKeySpec(sharedSecret, 0, 16, "AES");

            // receiving msg
            final byte[] ctReceived = receive("alice");
            final byte[] ivReceived = receive("alice");
            System.out.printf("CT RECEIVED BOB:  %s%n", Agent.hex(ctReceived));
            System.out.printf("IV RECEIVED BOB: %s%n", Agent.hex(ivReceived));

            // decrypt
            final Cipher bob = Cipher.getInstance("AES/GCM/NoPadding") ;
            final GCMParameterSpec specs = new GCMParameterSpec(128, ivReceived);
            bob.init(Cipher.DECRYPT_MODE, aesKey, specs);
            final byte[] ptReceived = bob.doFinal(ctReceived);
            System.out.printf("PT RECEIVED BOB:  %s%n", Agent.hex(ptReceived));
            System.out.printf("MSG RECEIVED BOB: %s%n", new String(ptReceived, StandardCharsets.UTF_8));
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}