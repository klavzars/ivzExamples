package isp.integrity;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;

/**
 * TASK:
 * Assuming Alice and Bob know a shared secret key, secure the channel using a
 * AES in GCM. Then exchange ten messages between Alice and Bob.
 * <p>
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class A2AgentCommunicationGCM {
    public static void main(String[] args) throws Exception {
        /*
         * Alice and Bob share a secret session key that will be
         * used for AES in GCM.
         */
        final Key key = KeyGenerator.getInstance("AES").generateKey();

        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                for(int i = 0; i < 10; i++) {
                    // sending msg
                    // payload
                    final String text = "I hope you get this message intact and in secret. Kisses, Alice.";
                    final byte[] pt = text.getBytes(StandardCharsets.UTF_8);
                    System.out.printf("MSG ALICE: %s%n", text);
                    System.out.printf("PT ALICE:  %s%n", Agent.hex(pt));

                    // encrypt
                    final Cipher alice = Cipher.getInstance("AES/GCM/NoPadding");
                    alice.init(Cipher.ENCRYPT_MODE, key);
                    final byte[] ct = alice.doFinal(pt);
                    System.out.printf("CT ALICE:  %s%n", Agent.hex(ct));

                    // send IV
                    final byte[] iv = alice.getIV();
                    System.out.printf("IV ALICE:  %s%n", Agent.hex(iv));


                    send("bob", ct);
                    send("bob", iv);

                    // receiving msg
                    final byte[] ctReceived = receive("bob");
                    final byte[] ivReceived = receive("bob");
                    System.out.printf("CT RECEIVED ALICE:  %s%n", Agent.hex(ctReceived));
                    System.out.printf("IV RECEIVED ALICE: %s%n", Agent.hex(ivReceived));

                    // decrypt
                    // the length of the MAC tag is either 128, 120, 112, 104 or 96 bits
                    // the default is 128 bits
                    final GCMParameterSpec specs = new GCMParameterSpec(128, ivReceived);
                    alice.init(Cipher.DECRYPT_MODE, key, specs);
                    final byte[] ptReceived = alice.doFinal(ctReceived);
                    System.out.printf("PT RECEIVED ALICE:  %s%n", Agent.hex(ptReceived));
                    System.out.printf("MSG RECEIVED ALICE: %s%n", new String(ptReceived, StandardCharsets.UTF_8));
                }

            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                for(int i = 0; i < 10; i++) {
                    // receiving msg
                    final byte[] ctReceived = receive("alice");
                    final byte[] ivReceived = receive("alice");
                    System.out.printf("CT RECEIVED BOB:  %s%n", Agent.hex(ctReceived));
                    System.out.printf("IV RECEIVED BOB: %s%n", Agent.hex(ivReceived));

                    // decrypt
                    final Cipher bob = Cipher.getInstance("AES/GCM/NoPadding");
                    // the length of the MAC tag is either 128, 120, 112, 104 or 96 bits
                    // the default is 128 bits
                    final GCMParameterSpec specs = new GCMParameterSpec(128, ivReceived);
                    bob.init(Cipher.DECRYPT_MODE, key, specs);
                    final byte[] ptReceived = bob.doFinal(ctReceived);
                    System.out.printf("PT RECEIVED BOB:  %s%n", Agent.hex(ptReceived));
                    System.out.printf("MSG RECEIVED BOB: %s%n", new String(ptReceived, StandardCharsets.UTF_8));

                    // sending msg
                    // payload
                    final String text = "I hope you stop talking once and for all. Bye.";
                    final byte[] pt = text.getBytes(StandardCharsets.UTF_8);
                    System.out.printf("MSG BOB: %s%n", text);
                    System.out.printf("PT BOB:  %s%n", Agent.hex(pt));

                    // encrypt
                    bob.init(Cipher.ENCRYPT_MODE, key);
                    final byte[] ct = bob.doFinal(pt);
                    System.out.printf("CT BOB:  %s%n", Agent.hex(ct));

                    // send IV
                    final byte[] iv = bob.getIV();
                    System.out.printf("IV BOB:  %s%n", Agent.hex(iv));


                    send("alice", ct);
                    send("alice", iv);
                }
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
