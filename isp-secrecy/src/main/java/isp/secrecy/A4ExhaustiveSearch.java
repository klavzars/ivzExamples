package isp.secrecy;

import fri.isp.Agent;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import java.lang.reflect.Array;
import java.security.Key;
import java.util.Arrays;

/**
 * Implement a brute force key search (exhaustive key search) if you know that the
 * message is:
 * "I would like to keep this text confidential Bob. Kind regards, Alice."
 * <p>
 * Assume the message was encrypted with "DES/ECB/PKCS5Padding".
 * Also assume that the key was poorly chosen. In particular, as an attacker,
 * you are certain that all bytes in the key, with the exception of the last three bytes,
 * have been set to 0.
 * <p>
 * The length of DES key is 8 bytes.
 * <p>
 * To manually specify a key, use the class {@link javax.crypto.spec.SecretKeySpec})
 */
public class A4ExhaustiveSearch {


    public static void main(String[] args) throws Exception {

        byte[] customKey = new byte[] {0, 0, 0, 0, 0, -50, 45, 110};
        SecretKeySpec key = new SecretKeySpec(customKey,"DES");

        final String message = "I would like to keep this text confidential Bob. Kind regards, Alice.";
        System.out.println("[MESSAGE] " + message);

        final byte[] pt = message.getBytes();
        System.out.println("[PT] " + Agent.hex(pt));
        final Cipher encrypt = Cipher.getInstance("DES/ECB/PKCS5Padding");
        encrypt.init(Cipher.ENCRYPT_MODE, key);
        final byte[] cipherText = encrypt.doFinal(pt);

        System.out.println("[KEY] " + (Arrays.toString(key.getEncoded())));
        System.out.println("[CT] " + Agent.hex(cipherText));

        bruteForceKey(cipherText, "I would like to keep this text confidential Bob. Kind regards, Alice.");
    }

    public static byte[] bruteForceKey(byte[] ct, String message) throws Exception {

        final byte[] pt = message.getBytes();

        byte[] customKey1 = new byte[]{0, 0, 0, 0, 0, 0, 0, 0};
        bruteForceRecursive(customKey1, 5, ct, pt);

        return null;
    }

    public static void bruteForceRecursive(byte[] key, int k, byte[] ct, byte[] pt) {
        if (k == key.length) {
            if (isKeyValid(key, ct, pt)) {
                System.out.println("CRACKED KEY: " + (Arrays.toString(key)));
            }
        } else {
            for (int i = -128; i < 128; i++) {
                key[k] = (byte) i;
                bruteForceRecursive(key, k + 1, ct, pt);
            }
        }
    }

    public static boolean isKeyValid(byte[] key, byte[] ct, byte[] pt) {
        try {
            final Cipher decrypt = Cipher.getInstance("DES/ECB/PKCS5Padding");
            SecretKeySpec key1 = new SecretKeySpec(key, "DES");

            decrypt.init(Cipher.DECRYPT_MODE, key1);
            final byte[] dt = decrypt.doFinal(ct);

            return Arrays.equals(pt, dt);

        } catch (Exception ex) {
//            System.out.println("ex");
            return false;
        }
    }
}

