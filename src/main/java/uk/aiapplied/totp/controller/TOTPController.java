package uk.aiapplied.totp.controller;

import uk.aiapplied.totp.service.TOTPService;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import com.google.zxing.WriterException;

@RestController
@RequestMapping("/api/totp")
public class TOTPController {

    @Autowired
    private TOTPService totpService;

    /**
     * Generate a new TOTP secret key and return it to the client.
     *
     * @return A response containing the secret key.
     */
    @PostMapping("/generate-secret")
    public ResponseEntity<String> generateSecret() {
        String secretKey = totpService.generateSecureSecret();
        return ResponseEntity.ok(secretKey);
    }

    /**
     * Generate a QR code for TOTP setup.
     *
     * @param secretKey The TOTP secret key.
     * @param username  The username associated with the TOTP.
     * @param issuer    The issuer (e.g., your app name).
     * @return A Base64-encoded QR code image.
     */
    @GetMapping("/generate-qr")
    public ResponseEntity<String> generateQRCode(
            @RequestParam String secretKey,
            @RequestParam String username,
            @RequestParam String issuer) {
        try {
            String qrCodeImage = totpService.getQRCodeImage(secretKey, username, issuer);
            return ResponseEntity.ok(qrCodeImage);
        } catch (WriterException | IOException e) {
            return ResponseEntity.status(500).body("Error generating QR code: " + e.getMessage());
        }
    }

    /**
     * Validate a user-provided TOTP code.
     *
     * @param secretKey The TOTP secret key.
     * @param totpCode  The user-provided TOTP code.
     * @return A response indicating whether the code is valid.
     */
    @PostMapping("/validate")
    public ResponseEntity<String> validateTOTP(
            @RequestParam String secretKey,
            @RequestParam String totpCode) {
        boolean isValid = totpService.validateTOTP(secretKey, totpCode);
        if (isValid) {
            return ResponseEntity.ok("TOTP validation successful.");
        } else {
            return ResponseEntity.badRequest().body("Invalid TOTP code.");
        }
    }
}
