package com.backendproject.main.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.backendproject.main.model.LoginModel;
import com.backendproject.main.model.User;
import com.backendproject.main.service.UserService;

@RestController
@RequestMapping("/login")
public class LoginController {

    @Autowired
    private UserService userService;

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    @PostMapping
    public ResponseEntity<String> login(@RequestBody LoginModel loginModel) {
        User user = userService.findUserByUsername(loginModel.getUsername());
        if (user == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials");
        }

        // Compare the hashed password from the login attempt with the hashed password in the database
        if (passwordEncoder.matches(loginModel.getPassword(), user.getPassword())) {
            // Passwords match, login successful
            return ResponseEntity.ok("Login successful");
        } else {
            // Passwords do not match, login failed
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials");
        }
    }
}