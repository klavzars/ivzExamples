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
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;

/*
 * Implement a key exchange between Alice and Bob using public-key encryption.
 * Once the shared secret is established, send an encrypted message from Alice to Bob using
 * AES in GCM.
 */
public class MidtermPractice {
    public static void main(String[] args) throws Exception {
        // Create two public-secret key pairs
        final String algorithm = "RSA/ECB/OAEPPadding";
        final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);

        final KeyPairGenerator kpgDH = KeyPairGenerator.getInstance("DH");
        kpgDH.initialize(2048);

        final KeyPair aliceKP = kpg.generateKeyPair();
        final KeyPair bobKP = kpg.generateKeyPair();

        final String signingAlgorithm =
                "SHA256withRSA";
//         "SHA256withDSA";
//                "SHA256withECDSA";
        final String keyAlgorithm =
                "RSA";
//         "DSA";
//                "EC";

        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {

            // alice sends public key
            final byte[] alicePK = aliceKP.getPublic().getEncoded();
            System.out.println(alicePK.length);
            send("bob", alicePK);


            // alice generates DH key pair
            final KeyPair keyPairDH = kpgDH.generateKeyPair();

            // send "PK" to bob ("PK": A = g^a, "SK": a)
            send("bob", keyPairDH.getPublic().getEncoded());
            print("My contribution: A = g^a = %s",
                    hex(keyPairDH.getPublic().getEncoded()));

            // get PK from bob
            final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(receive("bob"));
            final DHPublicKey bobPKDH = (DHPublicKey) KeyFactory.getInstance("DH")
                    .generatePublic(keySpec);

            // Run the agreement protocol
            final KeyAgreement dh = KeyAgreement.getInstance("DH");
            dh.init(keyPairDH.getPrivate());
            dh.doPhase(bobPKDH, true);

            // generate a shared AES key
            final byte[] sharedSecret = dh.generateSecret();
            print("Shared secret: g^ab = B^a = %s", hex(sharedSecret));

            // By default the shared secret will be 32 bytes long,
            // but our cipher requires keys of length 16 bytes
            // IMPORTANT: It is safer to not create the session key directly from
            // the shared secret, but derive it using key derivation function
            // (will be covered later)
            final SecretKeySpec aesKey = new SecretKeySpec(sharedSecret,
                    0, 16, "AES");
            final byte[] decryptedKey = aesKey.getEncoded();


//            // alice receives encrypted key, decrypts it
//            final byte[] ctReceived = receive("bob");
//            System.out.println("CT KEY received Alice: " + Agent.hex(ctReceived));
//            final Cipher rsaDec = Cipher.getInstance(algorithm);
//            rsaDec.init(Cipher.DECRYPT_MODE, aliceKP.getPrivate());
//            final byte[] decryptedKey = rsaDec.doFinal(ctReceived);

            System.out.println("KEY received Alice: " + Agent.hex(decryptedKey));

            // encrypts pt with aes and sends it
            final String textAlice = "I am alice this is my msg.";
            final byte[] pt = textAlice.getBytes(StandardCharsets.UTF_8);

            // alice computes digest, sends it to bob
            final MessageDigest digestAlgorithm = MessageDigest.getInstance("SHA-256");
            final byte[] digest = digestAlgorithm.digest(pt);
            send("bob", digest);

            // receive signature and timestamp
            final byte[] ctSignatureReceived = receive("bob");
            final byte[] ivSignatureReceived = receive("bob");
            final byte[] ctTimestampReceived = receive("bob");
            final byte[] ivTimestampReceived = receive("bob");
            System.out.printf("CT SIGNATURE RECEIVED:  %s%n", Agent.hex(ctSignatureReceived));
                System.out.printf("IV SIGNATURE RECEIVED:  %s%n", Agent.hex(ivSignatureReceived));

            // decrypt signature and timestamp
            // signature
            final Cipher aliceDec = Cipher.getInstance("AES/GCM/NoPadding") ;
            final GCMParameterSpec specs = new GCMParameterSpec(128, ivSignatureReceived);
            aliceDec.init(Cipher.DECRYPT_MODE, new SecretKeySpec(decryptedKey, "AES"), specs);
            final byte[] signatureReceived = aliceDec.doFinal(ctSignatureReceived);
//            System.out.printf("PT SIGNATURE RECEIVED:  %s%n", Agent.hex(signatureReceived));

            // timestamp
            final GCMParameterSpec specsTimestamp = new GCMParameterSpec(128, ivTimestampReceived);
            aliceDec.init(Cipher.DECRYPT_MODE, new SecretKeySpec(decryptedKey, "AES"), specsTimestamp);
            final byte[] timestampReceived = aliceDec.doFinal(ctTimestampReceived);
//            System.out.printf("PT TIMESTAMP RECEIVED:  %s%n", Agent.hex(timestampReceived));

            System.out.println("Signature received: " + Agent.hex(signatureReceived));
            System.out.println("Timestamp received: " + Agent.hex(timestampReceived));

            // verify signature
            final byte[] dataSignatureTimestamp = ByteBuffer.allocate(pt.length + signatureReceived.length + timestampReceived.length)
                    .put(pt).put(signatureReceived).put(timestampReceived).array();

            final byte[] digestAndTimestamp = ByteBuffer.allocate(digest.length + timestampReceived.length).put(digest).put(timestampReceived).array();
            final byte[] appendedAndHashed = digestAlgorithm.digest(digestAndTimestamp);


            final Signature verifier = Signature.getInstance(signingAlgorithm);
            verifier.initVerify(bobKP.getPublic());
            verifier.update(appendedAndHashed);
            if (verifier.verify(signatureReceived))
                System.out.println("Valid signature.");
            else
                System.err.println("Invalid signature.");

//            final Cipher alice = Cipher.getInstance("AES/GCM/NoPadding");
//            alice.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(decryptedKey, "AES"));
//            final byte[] ct = alice.doFinal(pt);
//            System.out.printf("CT ALICE:  %s%n", Agent.hex(ct));
//            final byte[] iv = alice.getIV();
//            System.out.printf("IV ALICE:  %s%n", Agent.hex(iv));
//
//            send("bob", ct);
//            send("bob", iv);


            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {

            // bob receives public key
            X509EncodedKeySpec alicePKSpec = new X509EncodedKeySpec(receive("alice"));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey alicePK = keyFactory.generatePublic(alicePKSpec);

            // get DH PK from alice
            final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(
                    receive("alice"));
            final DHPublicKey alicePKDH = (DHPublicKey) KeyFactory.getInstance("DH")
                    .generatePublic(keySpec);

            final DHParameterSpec dhParamSpec = alicePKDH.getParams();

            // create your own DH key pair
            final KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
            kpg.initialize(dhParamSpec);
            final KeyPair keyPair = kpg.generateKeyPair();
            send("alice", keyPair.getPublic().getEncoded());
            print("My contribution: B = g^b = %s",
                    hex(keyPair.getPublic().getEncoded()));

            final KeyAgreement dh = KeyAgreement.getInstance("DH");
            dh.init(keyPair.getPrivate());
            dh.doPhase(alicePKDH, true);

            final byte[] sharedSecret = dh.generateSecret();
            print("Shared secret: g^ab = A^b = %s", hex(sharedSecret));
            final SecretKeySpec key = new SecretKeySpec(sharedSecret, 0, 16, "AES");


//            //bob creates aes key
//            final Key key = KeyGenerator.getInstance("AES").generateKey();
//            final byte[] aesKey = key.getEncoded();
//            System.out.println("KEY generated Bob: " + Agent.hex(aesKey));
//
//            // encrypts and sends key
//            final Cipher rsaEnc = Cipher.getInstance(algorithm);
//            rsaEnc.init(Cipher.ENCRYPT_MODE, alicePK);
//            final byte[] ctKey = rsaEnc.doFinal(aesKey);
//            send("alice", ctKey);

            // receiving digest
            final byte[] digest = receive("alice");
            System.out.println("Digest received: " + Agent.hex(digest));

            // obtain timestamp
            long timestamp = System.currentTimeMillis();
            System.out.println("Timestamp: " + Agent.hex(ByteBuffer.allocate(8).putLong(timestamp).array()));

            // append timestamp to digest
            final byte[] digestWithTimestamp = ByteBuffer.allocate(digest.length + 8).put(digest).putLong(timestamp).array();
            System.out.println("Appended: " + Agent.hex(digestWithTimestamp));

            // hash digestWithTimestamp
            final MessageDigest digestAlgorithm = MessageDigest.getInstance("SHA-256");
            final byte[] appendedAndHashed = digestAlgorithm.digest(digestWithTimestamp);

            // sign digest+timestamp with bobs pk
            final Signature signer = Signature.getInstance(signingAlgorithm);
            signer.initSign(bobKP.getPrivate());
            signer.update(appendedAndHashed);
            final byte[] signature = signer.sign();
            System.out.println("Signature: " + Agent.hex(signature));

            // encrypt signature and timestamp - since it is a secure channel
            final Cipher bobEnc = Cipher.getInstance("AES/GCM/NoPadding");
            bobEnc.init(Cipher.ENCRYPT_MODE, key);
            final byte[] ctSignature = bobEnc.doFinal(signature);
            System.out.printf("CT SIGNATURE:  %s%n", Agent.hex(ctSignature));
            final byte[] ivSignature = bobEnc.getIV();
            System.out.printf("IV SIGNATURE:  %s%n", Agent.hex(ivSignature));


            bobEnc.init(Cipher.ENCRYPT_MODE, key);
            final byte[] ctTimestamp = bobEnc.doFinal(ByteBuffer.allocate(8).putLong(timestamp).array());
            System.out.printf("CT TIMESTAMP:  %s%n", Agent.hex(ctTimestamp));
            final byte[] ivTimestamp = bobEnc.getIV();
            System.out.printf("IV TIMESTAMP:  %s%n", Agent.hex(ivTimestamp));

            // return signature and timestamp with their ivs to alice
            send("alice", ctSignature);
            send("alice", ivSignature);
            send("alice", ctTimestamp);
            send("alice", ivTimestamp);

//            send("alice", ByteBuffer.allocate(8).putLong(timestamp).array());



//            final byte[] ctReceived = receive("alice");
//            final byte[] ivReceived = receive("alice");
//            System.out.printf("CT RECEIVED BOB:  %s%n", Agent.hex(ctReceived));
//            System.out.printf("IV RECEIVED BOB: %s%n", Agent.hex(ivReceived));
//
//            // decrypt
//            final Cipher bob = Cipher.getInstance("AES/GCM/NoPadding") ;
//            final GCMParameterSpec specs = new GCMParameterSpec(128, ivReceived);
//            bob.init(Cipher.DECRYPT_MODE, key, specs);
//            final byte[] ptReceived = bob.doFinal(ctReceived);
//            System.out.printf("PT RECEIVED BOB:  %s%n", Agent.hex(ptReceived));
//            System.out.printf("MSG RECEIVED BOB: %s%n", new String(ptReceived, StandardCharsets.UTF_8));
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}