package com.ecommerce.user.service;

import com.ecommerce.user.model.User;
import com.ecommerce.user.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.dao.DataIntegrityViolationException;
import com.ecommerce.user.exception.EmailAlreadyExistsException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Service
public class UserService {
    @Autowired
    private UserRepository userRepository;

    private static final Logger logger = LoggerFactory.getLogger(UserService.class);
    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    public User registerUser(User user) {
        if (userRepository.existsByEmail(user.getEmail())) {
            logger.warn("Tentativa de registro com e-mail já existente: {}", user.getEmail());
            throw new EmailAlreadyExistsException();
        }
        try {
            user.setPassword(passwordEncoder.encode(user.getPassword()));
            User saved = userRepository.save(user);
            logger.info("Usuário registrado: {}", saved.getEmail());
            return saved;
        } catch (DataIntegrityViolationException e) {
            logger.error("Erro de integridade ao registrar usuário: {}", user.getEmail());
            throw new EmailAlreadyExistsException();
        }
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