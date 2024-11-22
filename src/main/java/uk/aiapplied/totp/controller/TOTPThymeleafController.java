package uk.aiapplied.totp.controller;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import uk.aiapplied.totp.service.TOTPService;
import com.google.zxing.WriterException;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;

@Controller
@RequestMapping("/totp")
public class TOTPThymeleafController {
    @Autowired
    private TOTPService totpService;

    @GetMapping("/setup")
    public String setupTOTP(Model model) {
        String secretKey = totpService.generateSecureSecret();
        model.addAttribute("secretKey", secretKey);
        return "totp-setup";
    }

    @PostMapping("/generate-qr")
    public String generateQRCode(
            @RequestParam String secretKey,
            @RequestParam String username,
            @RequestParam String issuer,
            Model model) {
        try {
            String qrCodeImage = totpService.getQRCodeImage(secretKey, username, issuer);
            model.addAttribute("qrCodeImage", qrCodeImage);
            model.addAttribute("secretKey", secretKey);
            return "totp-qrcode";
        } catch (WriterException | IOException e) {
            model.addAttribute("errorMessage", "Error generating QR code: " + e.getMessage());
            return "error";
        }
    }

    @PostMapping("/validate")
    public String validateTOTP(
            @RequestParam String secretKey,
            @RequestParam String totpCode,
            Model model) {
        boolean isValid = totpService.validateTOTP(secretKey, totpCode);
        if (isValid) {
            model.addAttribute("successMessage", "TOTP validation successful.");
            return "totp-success";
        } else {
            model.addAttribute("errorMessage", "Invalid TOTP code. Please try again.");
            model.addAttribute("secretKey", secretKey);
            return "totp-validation";
        }
    }
}


