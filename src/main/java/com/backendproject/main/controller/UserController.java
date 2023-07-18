package com.backendproject.main.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import com.backendproject.main.model.User;
import com.backendproject.main.service.UserService;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

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

    @PostMapping("/post")
    public User createUser(@RequestBody User user) {
        String encryptedPassword = encryptPassword(user.getPassword());
        user.setPassword(encryptedPassword);
        return userService.saveUser(user);
    }

    @GetMapping("/{id}")
    public User getUserById(@PathVariable Long id) {
        User user = userService.findUserById(id);
        user.setPassword(decryptPassword(user.getPassword()));
        return user;
    }

    @GetMapping("/username/{username}")
    public User getUserByUsername(@PathVariable String username) {
        User user = userService.findUserByUsername(username);
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
            existingUser.setUsername(user.getUsername());
            existingUser.setPassword(user.getPassword());
            String encryptedPassword = encryptPassword(existingUser.getPassword());
            existingUser.setPassword(encryptedPassword);
            User updatedUser = userService.updateUser(existingUser);
            updatedUser.setPassword(decryptPassword(updatedUser.getPassword()));
            return updatedUser;
        } else {
            return null; 
        }
    }

    @DeleteMapping("/delete/{id}")
    public void deleteUser(@PathVariable Long id) {
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
            e.printStackTrace();
        }
        return password;
    }

    private String decryptPassword(String encryptedPassword) {
        try {
            SecretKeySpec secretKey = new SecretKeySpec(SECRET_KEY.getBytes(StandardCharsets.UTF_8), ALGORITHM);
            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedPassword));
            return new String(decryptedBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return encryptedPassword;
    }
}
