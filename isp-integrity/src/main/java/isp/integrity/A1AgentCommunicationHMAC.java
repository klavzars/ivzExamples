package isp.integrity;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * TASK:
 * Assuming Alice and Bob know a shared secret key, provide integrity to the channel
 * using HMAC implemted with SHA256. Then exchange ten messages between Alice and Bob.
 * <p>
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class A1AgentCommunicationHMAC {
    public static void main(String[] args) throws Exception {
        /*
         * Alice and Bob share a secret session key that will be
         * used for hash based message authentication code.
         */
        final Key key = KeyGenerator.getInstance("HmacSHA256").generateKey();

        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {

                for(int i = 0; i < 10; i++) {
                    // sending msg
                    final String text = "I hope you get this message intact. Kisses, Alice.";
                    final byte[] pt = text.getBytes(StandardCharsets.UTF_8);

                    // get hmac instance
                    final Mac alice = Mac.getInstance("HmacSHA256");

                    // get tag
                    alice.init(key);
                    final byte[] tag = alice.doFinal(pt);
//                    System.out.println("[Alice] PT: " + Agent.hex(pt));
//                    System.out.println("[Alice] HMAC TAG: " + Agent.hex(tag));

                    send("bob", pt);
                    send("bob", tag);

                    // receiving msg
                    final byte[] ptReceived = receive("bob");
                    final byte[] tagReceived = receive("bob");

                    // get tag
                    alice.init(key);
                    final byte[] tagCalculated = alice.doFinal(ptReceived);
//                    System.out.println("[Alice] RECEIVED PT: " + Agent.hex(ptReceived));
                    System.out.println("[Alice] RECEIVED HMAC TAG: " + Agent.hex(tagReceived));
                    System.out.println("[Alice] CALCULATED HMAC TAG: " + Agent.hex(tagCalculated));

                    final boolean isTagVerified = verify3(tagReceived, tagCalculated, key);
                    System.out.println("Do tags match: " + isTagVerified);
                }

            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                for(int i = 0; i < 10; i++) {
                    // receiving msg
                    final byte[] ptReceived = receive("alice");
                    final byte[] tagReceived = receive("alice");

                    // get hmac instance
                    final Mac bob = Mac.getInstance("HmacSHA256");

                    // get tag
                    bob.init(key);
                    final byte[] tagCalculated = bob.doFinal(ptReceived);
//                    System.out.println("[Bob] RECEIVED PT: " + Agent.hex(ptReceived));
                    System.out.println("[Bob] RECEIVED HMAC TAG: " + Agent.hex(tagReceived));
                    System.out.println("[Bob] CALCULATED HMAC TAG: " + Agent.hex(tagCalculated));

                    final boolean isTagVerified = verify3(tagReceived, tagCalculated, key);
                    System.out.println("Do tags match: " + isTagVerified);

                    // sending msg
                    final String text = "Leave me alone. Bob.";
                    final byte[] pt = text.getBytes(StandardCharsets.UTF_8);


                    // get tag
                    bob.init(key);
                    final byte[] tag = bob.doFinal(pt);
//                    System.out.println("[Bob] PT: " + Agent.hex(pt));
//                    System.out.println("[Bob] HMAC TAG: " + Agent.hex(tag));


                    send("alice", pt);
                    send("alice", tag);
                }
            }
        });

        env.connect("alice", "bob");
        env.start();
    }

    public static boolean verify3(byte[] tag1, byte[] tag2, Key key)
            throws NoSuchAlgorithmException, InvalidKeyException {
        /*
            FIXME: Defense #2

            The idea is to hide which bytes are actually being compared
            by MAC-ing the tags once more and then comparing those tags
         */
        final Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(key);

        final byte[] tagtag1 = mac.doFinal(tag1);
        final byte[] tagtag2 = mac.doFinal(tag2);

        return Arrays.equals(tagtag1, tagtag2);
    }
}
