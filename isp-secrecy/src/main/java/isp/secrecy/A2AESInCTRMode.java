package isp.secrecy;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import java.security.Key;

/**
 * TASK:
 * Assuming Alice and Bob know a shared secret key in advance, secure the channel using a
 * AES in counter mode. Then exchange ten messages between Alice and Bob.
 * <p>
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class A2AESInCTRMode {
    public static void main(String[] args) throws Exception {
        // STEP 1: Alice and Bob beforehand agree upon a cipher algorithm and a shared secret key
        // This key may be accessed as a global variable by both agents
        final Key key = KeyGenerator.getInstance("AES").generateKey();

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
                 * Do not forget: In CBC (and CTR mode), you have to also
                 * send the IV. The IV can be accessed via the
                 * cipher.getIV() call
                 */

                for (int i = 0; i < 10; i++) {
                    // sending
                    final byte[] pt = message.getBytes();
                    System.out.println("[PT] " + Agent.hex(pt));

                    final Cipher aes = Cipher.getInstance("AES/CTR/NoPadding");

                    aes.init(Cipher.ENCRYPT_MODE, key);
                    final byte[] iv = aes.getIV();

                    final byte[] cipherText = aes.doFinal(pt);

                    System.out.println("[CT] " + Agent.hex(cipherText));
                    System.out.println("[IV] " + Agent.hex(iv));

                    send("bob", iv);
                    send("bob", cipherText);

                    // receiving
                    final byte[] iv2 = receive("bob");
                    final byte[] cipherText2 = receive("bob");

                    print("Got " + Agent.hex(cipherText2));
                    print("Got " + Agent.hex(iv2));

                    IvParameterSpec ivSpec = new IvParameterSpec(iv2);
                    aes.init(Cipher.DECRYPT_MODE, key, ivSpec);
                    final byte[] dt = aes.doFinal(cipherText2);
                    System.out.println("[PT] " + Agent.hex(dt));
                    System.out.println("[MESSAGE] " + new String(dt));
                }
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                /* TODO STEP 4
                 * Bob receives, decrypts and displays a message.
                 * Once you obtain the byte[] representation of cipher parameters,
                 * you can load them with:
                 *
                 *   IvParameterSpec ivSpec = new IvParameterSpec(iv);
                 *   aes.init(Cipher.DECRYPT_MODE, my_key, ivSpec);
                 *
                 * You then pass this object to the cipher init() method call.*
                 */

                for (int i = 0; i < 10; i++) {
                    // receiving
                    final Cipher aes = Cipher.getInstance("AES/CTR/NoPadding");
                    final byte[] iv = receive("alice");
                    final byte[] cipherText = receive("alice");

                    print("Got " + Agent.hex(cipherText));
                    print("Got " + Agent.hex(iv));

                    IvParameterSpec ivSpec = new IvParameterSpec(iv);
                    aes.init(Cipher.DECRYPT_MODE, key, ivSpec);
                    final byte[] dt = aes.doFinal(cipherText);
                    System.out.println("[PT] " + Agent.hex(dt));
                    System.out.println("[MESSAGE] " + new String(dt));

                    // sending
                    // Bob's message
                    final String message = "I don't think about you at all.";

                    final byte[] pt = message.getBytes();
                    System.out.println("[PT] " + Agent.hex(pt));

                    aes.init(Cipher.ENCRYPT_MODE, key);
                    final byte[] iv2 = aes.getIV();

                    final byte[] cipherText2 = aes.doFinal(pt);

                    System.out.println("[CT2] " + Agent.hex(cipherText2));
                    System.out.println("[IV2] " + Agent.hex(iv2));

                    send("alice", iv2);
                    send("alice", cipherText2);


                }
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
