package isp.steganography;

import fri.isp.Agent;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.imageio.ImageIO;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Arrays;
import java.util.BitSet;

/**
 * Assignments:
 * <p>
 * 1. Change the encoding process, so that the first 4 bytes of the steganogram hold the
 * length of the payload. Then modify the decoding process accordingly.
 * 2. Add security: Provide secrecy and integrity for the hidden message. Use GCM for cipher.
 * Also, use AEAD to provide integrity to the steganogram size.
 * 3. Optional: Enhance the capacity of the carrier:
 * -- Use the remaining two color channels;
 * -- Use additional bits.
 */
public class ImageSteganography {

    public static void main(String[] args) throws Exception {
        final byte[] payload = "My secret message".getBytes(StandardCharsets.UTF_8);

//        ImageSteganography.encode(payload, "images/1_Kyoto.png", "images/steganogram.png");
//        final byte[] decoded = ImageSteganography.decode("images/steganogram.png");
//        System.out.printf("Decoded: %s%n", new String(decoded, StandardCharsets.UTF_8));

        /*
        TODO: Assignment 1 */
        ImageSteganography.encode(payload, "images/1_Kyoto.png", "images/steganogram.png");
        final byte[] decoded1 = ImageSteganography.decode("images/steganogram.png");
        System.out.printf("Decoded: %s%n", new String(decoded1, StandardCharsets.UTF_8));

        /*
        TODO: Assignment 2 */
        final SecretKey key = KeyGenerator.getInstance("AES").generateKey();
        ImageSteganography.encryptAndEncode(payload, "images/2_Morondava.png", "images/steganogram-encrypted.png", key);
        final byte[] decoded2 = ImageSteganography.decryptAndDecode("images/steganogram-encrypted.png", key);
        System.out.printf("Decoded: %s%n", new String(decoded2, StandardCharsets.UTF_8));
    }

    /**
     * Encodes given payload into the cover image and saves the steganogram.
     *
     * @param pt      The payload to be encoded
     * @param inFile  The filename of the cover image
     * @param outFile The filename of the steganogram
     * @throws IOException If the file does not exist, or the saving fails.
     */
    public static void encode(final byte[] pt, final String inFile, final String outFile) throws IOException {
        // load the image
        final BufferedImage image = loadImage(inFile);

        // Convert byte array to bit sequence
        final byte[] paddedPT = ByteBuffer.allocate(pt.length + 4).putInt(pt.length).put(pt).array();
        final BitSet bits = BitSet.valueOf(paddedPT);

        // encode the bits into image
        encodeBits(bits, image);

        // save the modified image into outFile
        saveImage(outFile, image);
    }

    /**
     * Decodes the message from given filename.
     *
     * @param fileName The name of the file
     * @return The byte array of the decoded message
     * @throws IOException If the filename does not exist.
     */
    public static byte[] decode(final String fileName) throws IOException {
        // load the image
        final BufferedImage image = loadImage(fileName);

        // read all LSBs
        final BitSet bits = decodeBits(image);

        // convert them to bytes
        final byte[] bytes = bits.toByteArray();
        return Arrays.copyOfRange(bytes, 4, bytes.length);
    }

    /**
     * Encrypts and encodes given plain text into the cover image and then saves the steganogram.
     *
     * @param pt      The plaintext of the payload
     * @param inFile  cover image filename
     * @param outFile steganogram filename
     * @param key     symmetric secret key
     * @throws Exception
     */
    public static void encryptAndEncode(final byte[] pt, final String inFile, final String outFile, final Key key)
            throws Exception {
        // TODO
        System.out.printf("PT:  %s%n", Agent.hex(pt));
        // encrypt
        final Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, key);

        final byte[] lengthOfData = ByteBuffer.allocate(4).putInt(pt.length).array();
        c.updateAAD(lengthOfData);
        final byte[] ct = c.doFinal(pt);
//        System.out.printf("DATA LEN:  %s%n", Agent.hex(lengthOfData));
        System.out.printf("CT:  %s%n", Agent.hex(ct));
//        System.out.printf("CT LEN:  %s%n", ct.length);

        // get iv
        final byte[] iv = c.getIV();
        System.out.printf("IV:  %s%n", Agent.hex(iv));

        // size + iv + ct
        final byte[] paddedCT = ByteBuffer.allocate(ct.length + iv.length + 4).putInt(ct.length + iv.length).put(iv).put(ct).array();

        System.out.printf("PADDED CT:  %s%n", Agent.hex(paddedCT));
//        System.out.printf("PADDED CT LEN:  %s%n", paddedCT.length);

        // load the image
        final BufferedImage image = loadImage(inFile);

        // Convert byte array to bit sequence
        final BitSet bits = BitSet.valueOf(paddedCT);

        // encode the bits into image
        encodeBits(bits, image);

        // save the modified image into outFile
        saveImage(outFile, image);
    }

    /**
     * Decrypts and then decodes the message from the steganogram.
     *
     * @param fileName name of the steganogram
     * @param key      symmetric secret key
     * @return plaintext of the decoded message
     * @throws Exception
     */
    public static byte[] decryptAndDecode(final String fileName, final Key key) throws Exception {
        // TODO
        // load the image
        final BufferedImage image = loadImage(fileName);

        // read all LSBs
        final BitSet bits = decodeBits(image);
//        System.out.println("BITS BEFORE DECRYPTION: " + bits.size());

        // convert them to bytes
        final byte[] paddedCt = bits.toByteArray();
        System.out.println("EVERYTHING RECEIVED: " + Agent.hex(paddedCt));
//        System.out.println("EVERYTHING RECEIVED LEN: " + paddedCt.length);

        final byte[] iv = Arrays.copyOfRange(paddedCt, 4, 16);
        final byte[] ct = Arrays.copyOfRange(paddedCt, 16, paddedCt.length);
        System.out.println("CT RECEIVED: " + Agent.hex(ct));
        System.out.println("IV RECEIVED: " + Agent.hex(iv));



        // decrypt
        final Cipher decrypt = Cipher.getInstance("AES/GCM/NoPadding");
        final GCMParameterSpec specs = new GCMParameterSpec(128, iv);
        decrypt.init(Cipher.DECRYPT_MODE, key, specs);

        decrypt.updateAAD(ByteBuffer.allocate(4).putInt(ct.length - 16).array());

        final byte[] ptReceived = decrypt.doFinal(ct);
        System.out.printf("PT RECEIVED:  %s%n", Agent.hex(ptReceived));
//        System.out.printf("MSG RECEIVED: %s%n", new String(ptReceived, StandardCharsets.UTF_8));

        return ptReceived;
    }

    /**
     * Loads an image from given filename and returns an instance of the BufferedImage
     *
     * @param inFile filename of the image
     * @return image
     * @throws IOException If file does not exist
     */
    protected static BufferedImage loadImage(final String inFile) throws IOException {
        return ImageIO.read(new File(inFile));
    }

    /**
     * Saves given image into file
     *
     * @param outFile image filename
     * @param image   image to be saved
     * @throws IOException If an error occurs while writing to file
     */
    protected static void saveImage(String outFile, BufferedImage image) throws IOException {
        ImageIO.write(image, "png", new File(outFile));
    }

    /**
     * Encodes bits into image. The algorithm modifies the least significant bit
     * of the red RGB component in each pixel.
     *
     * @param payload Bits to be encoded
     * @param image   The image onto which the payload is to be encoded
     */
    protected static void encodeBits(final BitSet payload, final BufferedImage image) {
        for (int x = image.getMinX(), bitCounter = 0; x < image.getWidth() && bitCounter < payload.size(); x++) {
            for (int y = image.getMinY(); y < image.getHeight() && bitCounter < payload.size(); y++) {
                final Color original = new Color(image.getRGB(x, y));

                // Let's modify the red component only
                final int newRed = payload.get(bitCounter) ?
                        original.getRed() | 0x01 : // sets LSB to 1
                        original.getRed() & 0xfe;  // sets LSB to 0

                // Create a new color object
                final Color modified = new Color(newRed, original.getGreen(), original.getBlue());

                // Replace the current pixel with the new color
                image.setRGB(x, y, modified.getRGB());

                // Uncomment to see changes in the RGB components
                // System.out.printf("%03d bit [%d, %d]: %s -> %s%n", bitCounter, x, y, original, modified);

                bitCounter++;
            }
        }
    }

    /**
     * Decodes the message from the steganogram
     *
     * @param image steganogram
     * @return {@link BitSet} instance representing the sequence of read bits
     */
    protected static BitSet decodeBits(final BufferedImage image) {
        final BitSet bits = new BitSet();
        int sizeBits = 32;

        for (int x = image.getMinX(), bitCounter = 0; x < image.getWidth() && bitCounter < sizeBits; x++) {
            for (int y = image.getMinY(); y < image.getHeight() && bitCounter < sizeBits; y++) {
                final Color color = new Color(image.getRGB(x, y));
                final int lsb = color.getRed() & 0x01;
                bits.set(bitCounter, lsb == 0x01);
                bitCounter++;

                if (bitCounter == 32) {
                    sizeBits += 8 * ByteBuffer.wrap(bits.toByteArray()).getInt();
                }
            }
        }
        return bits;
    }
}
