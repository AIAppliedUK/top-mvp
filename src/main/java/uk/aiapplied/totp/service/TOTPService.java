package uk.aiapplied.totp.service;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;

import org.apache.commons.codec.binary.Base32;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.stream.IntStream;

@Service
public class TOTPService {

    private static final Logger logger = LoggerFactory.getLogger(TOTPService.class);
    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final int TOTP_LENGTH = 6;
    private static final int TIME_STEP = 30;
    private static final int SECRET_KEY_BYTES = 16; // 128-bit key

    /**
     * Generates a cryptographically secure, Base32-encoded secret key for TOTP.
     *
     * <p>This method creates a random secret key using a secure random number generator. 
     * The generated key is 128 bits (16 bytes) long and is encoded in Base32 format, 
     * which is compatible with TOTP applications like Google Authenticator or Microsoft Authenticator.</p>
     *
     * <p>Padding characters ('=') are removed from the Base32-encoded string 
     * to conform to the expected format for TOTP secret keys.</p>
     *
     * @return A Base32-encoded secret key as a string.
     */
    public String generateSecureSecret() {
        byte[] bytes = new byte[SECRET_KEY_BYTES];
        new SecureRandom().nextBytes(bytes);
        return new Base32().encodeToString(bytes).replace("=", ""); // Remove padding
    }

    /**
     * Generates a Time-based One-Time Password (TOTP) based on a shared secret key and a time interval.
     * <p>
     * This method implements the TOTP algorithm as defined in RFC 6238. It computes a one-time
     * password that is valid for a specific time interval, typically used for multi-factor authentication.
     * </p>
     *
     * @param secretKey   The shared secret key encoded in Base32 format. This key is shared between
     *                    the server and the client and must remain confidential.
     * @param timeInterval The current time interval (in seconds or milliseconds, depending on implementation)
     *                    that determines the validity of the generated TOTP.
     * @return A string representation of the generated TOTP, formatted as a zero-padded numeric code
     *         with a fixed length specified by {@code TOTP_LENGTH}.
     * @throws Exception If an error occurs during the TOTP generation process, such as invalid input or 
     *                   cryptographic failures.
     *
     * <h3>How It Works:</h3>
     * <ol>
     *   <li>Decodes the {@code secretKey} from Base32 format to its binary representation.</li>
     *   <li>Converts the {@code timeInterval} into a byte array suitable for HMAC hashing.</li>
     *   <li>Calculates an HMAC-SHA1 hash using the decoded secret key and the time interval bytes.</li>
     *   <li>Extracts a 4-byte segment of the hash based on the dynamic offset, derived from the last byte of the hash.</li>
     *   <li>Interprets the extracted bytes as a 31-bit integer to compute the binary code.</li>
     *   <li>Applies a modulus operation to the binary code to produce the TOTP with a specific number of digits
     *       ({@code TOTP_LENGTH}).</li>
     *   <li>Formats the TOTP as a zero-padded string to ensure consistent length.</li>
     * </ol>
     *
     * <h3>Example Usage:</h3>
     * <pre>{@code
     * String secretKey = "JBSWY3DPEHPK3PXP"; // Example Base32 encoded secret key
     * long timeInterval = System.currentTimeMillis() / 30000; // 30-second time window
     *
     * try {
     *     String totp = generateTOTP(secretKey, timeInterval);
     *     System.out.println("Generated TOTP: " + totp);
     * } catch (Exception e) {
     *     System.err.println("Error generating TOTP: " + e.getMessage());
     * }
     * }</pre>
     *
     * <h3>Dependencies:</h3>
     * <ul>
     *   <li>{@code decodeBase32(String)}: Decodes a Base32-encoded string into a byte array.</li>
     *   <li>{@code longToBytes(long)}: Converts a {@code long} value into a byte array.</li>
     *   <li>{@code calculateHMAC(byte[], byte[])}: Computes the HMAC-SHA1 hash of the input data using the provided key.</li>
     *   <li>{@code TOTP_LENGTH}: A constant defining the number of digits in the generated TOTP.</li>
     *   <li>{@code logger}: An instance of a logging framework (e.g., SLF4J) used to log errors.</li>
     * </ul>
     *
     * <h3>Notes:</h3>
     * <ul>
     *   <li>The method assumes {@code TOTP_LENGTH} is a predefined constant representing the desired TOTP length.</li>
     *   <li>The {@code timeInterval} should be consistent across the server and client for the TOTP to match.</li>
     *   <li>Ensure the {@code secretKey} is securely stored and never exposed to unauthorised parties.</li>
     * </ul>
     */
    public String generateTOTP(String secretKey, long timeInterval) throws Exception {
        try {
            byte[] decodedKey = decodeBase32(secretKey);
            byte[] timeBytes = longToBytes(timeInterval);
            byte[] hash = calculateHMAC(decodedKey, timeBytes);

            int offset = hash[hash.length - 1] & 0xF;
            long binaryCode = ((hash[offset] & 0x7F) << 24) |
                              ((hash[offset + 1] & 0xFF) << 16) |
                              ((hash[offset + 2] & 0xFF) << 8) |
                              (hash[offset + 3] & 0xFF);

            int totp = (int) (binaryCode % Math.pow(10, TOTP_LENGTH));
            return String.format("%0" + TOTP_LENGTH + "d", totp);
        } catch (Exception e) {
            logger.error("Failed to generate TOTP", e);
            throw new Exception("Failed to generate TOTP", e);   
        }
    }

    /**
     * Validates a user-provided TOTP (Time-based One-Time Password) against the expected value.
     *
     * <p>This method checks if the given TOTP code matches the one generated for the current 
     * time interval or the adjacent intervals (previous and next). This provides a time drift 
     * tolerance of ±1 time step (default: 30 seconds) to account for minor clock discrepancies 
     * between the server and the client device.</p>
     *
     * <p>If the TOTP does not match any of the valid codes, the method logs a warning indicating 
     * an invalid TOTP attempt.</p>
     *
     * @param secretKey The Base32-encoded secret key used to generate the TOTP.
     * @param inputTOTP The TOTP code provided by the user.
     * @return {@code true} if the TOTP is valid for the current or adjacent time intervals, 
     *         {@code false} otherwise.
     */
    public boolean validateTOTP(String secretKey, String inputTOTP) {
        long currentInterval = System.currentTimeMillis() / 1000 / TIME_STEP;
        boolean isValid = IntStream.rangeClosed(-1, 1)
            .mapToObj(i -> {
                try {
                    return generateTOTP(secretKey, currentInterval + i);
                } catch (Exception e) {
                    logger.error("TOTP generation failed during validation", e);
                    return null;
                }
            })
            .anyMatch(inputTOTP::equals);

        if (!isValid) {
            logger.warn("Invalid TOTP attempt for secretKey: {}", secretKey);
        }
        return isValid;
    }

    /**
     * Generates a Base64-encoded QR code image for TOTP setup.
     *
     * <p>This method creates a QR code that encodes the TOTP setup URL in a format compatible with 
     * TOTP-compatible applications, such as Google Authenticator and Microsoft Authenticator. The 
     * QR code includes the secret key, username, issuer (e.g., application name), algorithm, 
     * TOTP code length, and time step interval.</p>
     *
     * <p>The generated QR code image is encoded in Base64 format, making it easy to embed in HTML 
     * or send as part of an API response.</p>
     *
     * @param secretKey The Base32-encoded secret key for the TOTP.
     * @param username  The username associated with the TOTP (typically a unique identifier for the user).
     * @param issuer    The application or service name that provides the TOTP.
     * @return A Base64-encoded string representing the QR code image in PNG format.
     * @throws IllegalArgumentException If {@code username} or {@code issuer} is null or empty.
     * @throws WriterException          If an error occurs while generating the QR code.
     * @throws IOException              If an error occurs while encoding the QR code image.
     */
    public String getQRCodeImage(String secretKey, String username, String issuer) throws WriterException, IOException {
        if (username == null || username.isEmpty() || issuer == null || issuer.isEmpty()) {
            throw new IllegalArgumentException("Username and issuer must not be null or empty");
        }
        String otpAuthURL = String.format(
            "otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA256&digits=%d&period=%d",
            issuer, username, secretKey, issuer, TOTP_LENGTH, TIME_STEP
        );
        return generateQRCode(otpAuthURL);
    }

    private byte[] decodeBase32(String secretKey) {
        return new Base32().decode(secretKey);
    }

    /**
     * Computes the HMAC (Hash-based Message Authentication Code) for the given data using the specified key.
     *
     * <p>This method uses the HMAC algorithm defined by {@code HMAC_ALGORITHM} (e.g., HmacSHA256) to 
     * generate a hash-based authentication code. It initializes a {@link Mac} instance with the provided 
     * key and processes the input data to compute the HMAC.</p>
     *
     * @param key  The secret key used for the HMAC computation.
     * @param data The input data to be hashed.
     * @return A byte array representing the computed HMAC value.
     * @throws Exception If an error occurs during HMAC initialization or computation, such as 
     *                   an invalid key or unsupported algorithm.
     */
    private byte[] calculateHMAC(byte[] key, byte[] data) throws Exception {
        Mac hmac = Mac.getInstance(HMAC_ALGORITHM);
        hmac.init(new SecretKeySpec(key, HMAC_ALGORITHM));
        return hmac.doFinal(data);
    }

    /**
     * Converts a long value to an 8-byte array in big-endian order.
     *
     * <p>This method takes a 64-bit long value and converts it into an array of 8 bytes, 
     * where the most significant byte is stored at the lowest index (big-endian format). 
     * This representation is commonly used in cryptographic and network protocols.</p>
     *
     * @param value The long value to be converted.
     * @return An 8-byte array representing the input long value in big-endian order.
     */
    private byte[] longToBytes(long value) {
        byte[] bytes = new byte[8];
        for (int i = 7; i >= 0; i--) {
            bytes[i] = (byte) (value & 0xFF);
            value >>= 8;
        }
        return bytes;
    }

    /**
     * Generates a QR code from the provided data and returns it as a Base64-encoded string.
     *
     * <p>This method takes an input string, encodes it into a QR code using the {@link QRCodeWriter} class, 
     * converts the QR code into a PNG image, and then encodes the resulting image as a Base64 string. 
     * The output is suitable for embedding in web pages or sending as part of an API response.</p>
     *
     * @param data The input data to be encoded in the QR code.
     * @return A Base64-encoded string representing the QR code image in PNG format.
     * @throws WriterException If an error occurs while generating the QR code.
     * @throws IOException If an error occurs while encoding the QR code image.
     */
    private String generateQRCode(String data) throws WriterException, IOException {
        BitMatrix bitMatrix = new QRCodeWriter().encode(data, BarcodeFormat.QR_CODE, 250, 250);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        MatrixToImageWriter.writeToStream(bitMatrix, "PNG", outputStream);
        return Base64.getEncoder().encodeToString(outputStream.toByteArray());
    }
}
