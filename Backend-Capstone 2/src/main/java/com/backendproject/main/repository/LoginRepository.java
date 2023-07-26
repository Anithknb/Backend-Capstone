package com.backendproject.main.repository;

import com.backendproject.main.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface LoginRepository extends JpaRepository<User, Long> {
    User findByUsername(String username);
}
