package com.ecommerce.user.service;

import com.ecommerce.user.model.User;
import com.ecommerce.user.model.dto.RegistrationRequest;
import com.ecommerce.user.model.dto.UserResponse;
import com.ecommerce.user.repository.UserRepository;
import com.ecommerce.user.exception.UserAlreadyExistsException;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Service
public class UserService {

    private static final Logger logger = LoggerFactory.getLogger(UserService.class);

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = null;
        this.passwordEncoder = passwordEncoder;
    }

    public UserResponse registerUser(RegistrationRequest registrationRequest) {
        if (userRepository.existsByEmail(registrationRequest.getEmail())) {
            logger.warn("Attempt to register with already existing email: {}", registrationRequest.getEmail());
            throw new UserAlreadyExistsException("User with email " + registrationRequest.getEmail() + " already exists.");
        }

        User newUser = new User();
        newUser.setName(registrationRequest.getName());
        newUser.setEmail(registrationRequest.getEmail());
        newUser.setPassword(passwordEncoder.encode(registrationRequest.getPassword()));

        User savedUser = userRepository.save(newUser);
        logger.info("User registered successfully: {}", savedUser.getEmail());

        return new UserResponse(savedUser.getId(), savedUser.getName(), savedUser.getEmail());
    }

    public User authenticate(String email, String password) {
        return userRepository.findByEmail(email)
                .filter(user -> passwordEncoder.matches(password, user.getPassword()))
                .map(user -> {
                    logger.info("Login bem-sucedido para: {}", email);
                    return user;
                })
                .orElseGet(() -> {
                    logger.warn("Tentativa de login falhou para: {}", email);
                    return null;
                });
    }

    public User findByEmail(String email) {
        return userRepository.findByEmail(email).orElse(null);
    }

    public User updateUser(String email, User updatedUser) {
        User user = userRepository.findByEmail(email).orElse(null);
        if (user == null) return null;
        user.setName(updatedUser.getName());
        // Não atualizar email nem senha aqui por segurança
        return userRepository.save(user);
    }

    public boolean deleteByEmail(String email) {
        User user = userRepository.findByEmail(email).orElse(null);
        if (user == null) return false;
        userRepository.delete(user);
        return true;
    }
} 