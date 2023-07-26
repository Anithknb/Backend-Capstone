package com.backendproject.main.service;

import com.backendproject.main.model.LoginModel;
import com.backendproject.main.model.User;
import com.backendproject.main.repository.LoginRepository;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class LoginService {

    @Autowired
    private LoginRepository loginRepository;

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    public boolean loginUser(LoginModel loginModel) {
        String username = loginModel.getUsername();
        String password = loginModel.getPassword();

        User user = loginRepository.findByUsername(username);
        if (user != null) {
            return passwordEncoder.matches(password, user.getPassword());
        }

        return false;
    }
}
