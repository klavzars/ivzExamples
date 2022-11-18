package isp.signatures;

import fri.isp.Agent;
import fri.isp.Environment;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;

/*
 * Assuming Alice and Bob know each other's public key, provide integrity and non-repudiation
 * to exchanged messages with ECDSA. Then exchange ten signed messages between Alice and Bob.
 */
public class A2AgentCommunicationSignature {
    public static void main(String[] args) throws Exception {
        final Environment env = new Environment();

        final String signingAlgorithm = "SHA256withECDSA";
        final String keyAlgorithm = "EC";

        // Create key pairs
        final KeyPair keyAlice = KeyPairGenerator.getInstance(keyAlgorithm).generateKeyPair();
        final KeyPair keyBob = KeyPairGenerator.getInstance(keyAlgorithm).generateKeyPair();

        final String[] msgAlice = {"Whaddup bobby boi", "How are you today", "k byee",
                "k byeeee", "k byeeeee", "k byeeeeee", "k byeeeeeee",
                "k byeeeeeeee", "k beeeeeeeeeee", "k byeeeeeeeeeeeeeee"};

        final String[] msgBob = {"Whazzzzzup Alice", "Im terrible actually", "cya",
                "cyaa", "cyaaa", "cyaaaa", "cyaaaaa", "cyaaaaaa", "cyaaaaaaaa", "cyaaaaaaaaaaaaa"};

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                for (int i = 0; i < msgAlice.length; i++) {
                    // create a message, sign it,
                    // and send the message, signature pair to bob
                    final String document = msgAlice[i];
                    final Signature aliceSigner = Signature.getInstance(signingAlgorithm);
                    aliceSigner.initSign(keyAlice.getPrivate());
                    aliceSigner.update(document.getBytes(StandardCharsets.UTF_8));
                    final byte[] signature = aliceSigner.sign();
                    System.out.println("[Alice] Msg: " + document);
                    System.out.println("[Alice] Signature: " + Agent.hex(signature));

                    send("bob", document.getBytes(StandardCharsets.UTF_8));
                    send("bob", signature);

                    // receiving msg and signature
                    final byte[] receivedDoc = receive("bob");
                    final byte[] receivedSignature = receive("bob");

                    // checking signature
                    final Signature verifier = Signature.getInstance(signingAlgorithm);
                    verifier.initVerify(keyBob.getPublic());
                    verifier.update(receivedDoc);
                    System.out.println("[Alice] Signature is verified: " + verifier.verify(receivedSignature));
                }
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                for (int i = 0; i < msgBob.length; i++) {
                    // receiving msg and signature
                    final byte[] receivedDoc = receive("alice");
                    final byte[] receivedSignature = receive("alice");

                    // checking signature
                    final Signature verifier = Signature.getInstance(signingAlgorithm);
                    verifier.initVerify(keyAlice.getPublic());
                    verifier.update(receivedDoc);
                    System.out.println("[Bob] Signature is verified: " + verifier.verify(receivedSignature));

                    // create a message, sign it,
                    // and send the message, signature pair to bob
                    final String document = msgBob[i];
                    final Signature bobSigner = Signature.getInstance(signingAlgorithm);
                    bobSigner.initSign(keyBob.getPrivate());
                    bobSigner.update(document.getBytes(StandardCharsets.UTF_8));
                    final byte[] signature = bobSigner.sign();
                    System.out.println("[Bob] Msg: " + document);
                    System.out.println("[Bob] Signature: " + Agent.hex(signature));

                    send("alice", document.getBytes(StandardCharsets.UTF_8));
                    send("alice", signature);
                }
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}