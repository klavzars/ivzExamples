package isp.secrecy;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.ChaCha20ParameterSpec;
import java.nio.ByteBuffer;
import java.security.Key;
import java.security.SecureRandom;

/**
 * TASK:
 * Assuming Alice and Bob know a shared secret key in advance, secure the channel using
 * ChaCha20 stream cipher. Then exchange ten messages between Alice and Bob.
 * <p>
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class A3ChaCha20 {
    public static void main(String[] args) throws Exception {
        // STEP 1: Alice and Bob beforehand agree upon a cipher algorithm and a shared secret key
        // This key may be accessed as a global variable by both agents
        final Key key = KeyGenerator.getInstance("Chacha20").generateKey();

        // STEP 2: Setup communication
        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                final String message = "I love you Bob. Kisses, Alice.";

                /* TODO STEP 3:
                 * Alice creates, encrypts and sends a message to Bob. Bob replies to the message.
                 * Such exchange repeats 10 times.
                 *
                 * Recall, ChaCha2 requires that you specify the nonce and the counter explicitly.
                 */

                for (int i = 0; i < 10; i++) {
                    // sending
                    final byte[] pt = message.getBytes();
                    System.out.println("[PT] " + Agent.hex(pt));

                    final Cipher chaCha20 = Cipher.getInstance("ChaCha20");

                    byte[] nonce = new byte[12];
                    new SecureRandom().nextBytes(nonce);
                    int counter = 1;

                    ChaCha20ParameterSpec paramSpec = new ChaCha20ParameterSpec(nonce, counter);
                    chaCha20.init(Cipher.ENCRYPT_MODE, key, paramSpec);
                    final byte[] cipherText = chaCha20.doFinal(pt);

                    System.out.println("[CT] " + Agent.hex(cipherText));
                    System.out.println("[Nonce] " + Agent.hex(nonce));

                    send("bob", ByteBuffer.allocate(4).putInt(counter).array());
                    send("bob", nonce);
                    send("bob", cipherText);

                    // receiving
                    final byte[] counter2 = receive("bob");
                    final byte[] nonce2 = receive("bob");
                    final byte[] cipherText2 = receive("bob");

                    print("Got counter " + Agent.hex(counter2));
                    print("Got nonce " + Agent.hex(nonce2));
                    print("Got ct " + Agent.hex(cipherText2));

                    ChaCha20ParameterSpec paramSpec2 = new ChaCha20ParameterSpec(nonce2, ByteBuffer.wrap(counter2).getInt());
                    chaCha20.init(Cipher.DECRYPT_MODE, key, paramSpec2);
                    final byte[] dt = chaCha20.doFinal(cipherText2);
                    System.out.println("[PT] " + Agent.hex(dt));
                    System.out.println("[MESSAGE] " + new String(dt));
                }
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                // TODO

                for (int i = 0; i < 10; i++) {
                    // receiving
                    final Cipher chaCha20 = Cipher.getInstance("Chacha20");
                    final byte[] counter = receive("alice");
                    final byte[] nonce = receive("alice");
                    final byte[] cipherText = receive("alice");

                    print("Got counter " + Agent.hex(counter));
                    print("Got nonce " + Agent.hex(nonce));
                    print("Got ct " + Agent.hex(cipherText));

                    ChaCha20ParameterSpec paramSpec = new ChaCha20ParameterSpec(nonce, ByteBuffer.wrap(counter).getInt());
                    chaCha20.init(Cipher.DECRYPT_MODE, key, paramSpec);
                    final byte[] dt = chaCha20.doFinal(cipherText);
                    System.out.println("[PT] " + Agent.hex(dt));
                    System.out.println("[MESSAGE] " + new String(dt));

                    // sending
                    // Bob's message
                    final String message = "I don't think about you at all.";

                    final byte[] pt = message.getBytes();
                    System.out.println("[PT] " + Agent.hex(pt));

                    byte[] nonce2 = new byte[12];
                    new SecureRandom().nextBytes(nonce2);
                    int counter2 = 2;

                    ChaCha20ParameterSpec paramSpec2 = new ChaCha20ParameterSpec(nonce2, counter2);
                    chaCha20.init(Cipher.ENCRYPT_MODE, key, paramSpec2);
                    final byte[] cipherText2 = chaCha20.doFinal(pt);

                    System.out.println("[CT] " + Agent.hex(cipherText2));
                    System.out.println("[Nonce] " + Agent.hex(nonce2));

                    send("alice", ByteBuffer.allocate(4).putInt(counter2).array());
                    send("alice", nonce2);
                    send("alice", cipherText2);
                }
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
