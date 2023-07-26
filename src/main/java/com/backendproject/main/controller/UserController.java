package com.backendproject.main.controller;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.backendproject.main.model.User;
import com.backendproject.main.service.UserService;

@RestController
@RequestMapping("/users")
public class UserController {

    @Autowired
    private UserService userService;

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    private static final String SECRET_KEY = "0123456789abcdef0123456789abcdef"; // 32 bytes (256 bits)
    private static final String ALGORITHM = "AES";
    private static final String CIPHER_TRANSFORMATION = "AES/ECB/PKCS5Padding";

    // Password strength regex pattern to enforce specific criteria.
    private static final String PASSWORD_STRENGTH_PATTERN =
            "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=])(?=\\S+$).{8,}$";

    @PostMapping("/post")
    public ResponseEntity<?> createUser(@Valid @RequestBody User user, BindingResult bindingResult) {
        if (bindingResult.hasErrors()) {
            return new ResponseEntity<>("Invalid user data. Please check the request body.", HttpStatus.BAD_REQUEST);
        }

        String password = user.getPassword();
        String passwordStrengthError = checkPasswordStrength(password);
        if (passwordStrengthError != null) {
            return new ResponseEntity<>(passwordStrengthError, HttpStatus.BAD_REQUEST);
        }

        String encryptedPassword = encryptPassword(password);
        user.setPassword(encryptedPassword);
        return new ResponseEntity<>(userService.saveUser(user), HttpStatus.CREATED);
    }

    @GetMapping("/{id}")
    public User getUserById(@PathVariable Long id) {
        User user = userService.findUserById(id);
        if (user == null) {
            throw new NotFoundException("User with id " + id + " not found.");
        }
        user.setPassword(decryptPassword(user.getPassword()));
        return user;
    }

    @GetMapping("/username/{username}")
    public User getUserByUsername(@PathVariable String username) {
        User user = userService.findUserByUsername(username);
        if (user == null) {
            throw new NotFoundException("User with username " + username + " not found.");
        }
        user.setPassword(decryptPassword(user.getPassword()));
        return user;
    }

    @GetMapping("/getall")
    public List<User> getAllUsers() {
        List<User> users = userService.getAllUsers();
        for (User user : users) {
            user.setPassword(decryptPassword(user.getPassword()));
        }
        return users;
    }

    @PutMapping("/update/{id}")
    public User updateUser(@PathVariable Long id, @RequestBody User user) {
        User existingUser = userService.findUserById(id);
        if (existingUser != null) {
            String password = user.getPassword();
            String passwordStrengthError = checkPasswordStrength(password);
            if (passwordStrengthError != null) {
                throw new BadRequestException(passwordStrengthError);
            }

            existingUser.setUsername(user.getUsername());
            existingUser.setPassword(password);
            String encryptedPassword = encryptPassword(password);
            existingUser.setPassword(encryptedPassword);
            User updatedUser = userService.updateUser(existingUser);
            updatedUser.setPassword(decryptPassword(updatedUser.getPassword()));
            return updatedUser;
        } else {
            throw new NotFoundException("User with id " + id + " not found.");
        }
    }

    @DeleteMapping("/delete/{id}")
    public void deleteUser(@PathVariable Long id) {
        User user = userService.findUserById(id);
        if (user == null) {
            throw new NotFoundException("User with id " + id + " not found.");
        }
        userService.deleteUser(id);
    }

    private String encryptPassword(String password) {
        try {
            SecretKeySpec secretKey = new SecretKeySpec(SECRET_KEY.getBytes(StandardCharsets.UTF_8), ALGORITHM);
            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encryptedBytes = cipher.doFinal(password.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            throw new EncryptionException("Error encrypting password.", e);
        }
    }

    private String decryptPassword(String encryptedPassword) {
        try {
            SecretKeySpec secretKey = new SecretKeySpec(SECRET_KEY.getBytes(StandardCharsets.UTF_8), ALGORITHM);
            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedPassword));
            return new String(decryptedBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new EncryptionException("Error decrypting password.", e);
        }
    }

    // Method to validate the password strength against the defined pattern.
    private String checkPasswordStrength(String password) {
        Pattern pattern = Pattern.compile(PASSWORD_STRENGTH_PATTERN);
        Matcher matcher = pattern.matcher(password);

        if (!matcher.matches()) {
            StringBuilder errorMessage = new StringBuilder("Password does not meet the strength requirements. ");
            if (!password.matches(".*[A-Z].*")) {
                errorMessage.append("Capital letter is missing. ");
            }
            if (!password.matches(".*[a-z].*")) {
                errorMessage.append("Lowercase letter is missing. ");
            }
            if (!password.matches(".*[0-9].*")) {
                errorMessage.append("Digit is missing. ");
            }
            if (!password.matches(".*[@#$%^&+=].*")) {
                errorMessage.append("Special character is missing. ");
            }
            if (password.length() < 8) {
                errorMessage.append("Password should be at least 8 characters long. ");
            }
            return errorMessage.toString();
        }
        return null;
    }

    // Custom exception classes
    public static class NotFoundException extends RuntimeException {
       
		private static final long serialVersionUID = 1L;

		public NotFoundException(String message) {
            super(message);
        }
    }

    public static class EncryptionException extends RuntimeException {
       
		private static final long serialVersionUID = 1L;

		public EncryptionException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    public static class BadRequestException extends RuntimeException {
       
		private static final long serialVersionUID = 1L;

		public BadRequestException(String message) {
            super(message);
        }
    }
}
