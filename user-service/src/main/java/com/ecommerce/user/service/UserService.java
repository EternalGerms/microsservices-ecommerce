package com.ecommerce.user.service;

import com.ecommerce.user.model.Role;
import com.ecommerce.user.model.User;
import com.ecommerce.user.model.dto.RegistrationRequest;
import com.ecommerce.user.model.dto.UserResponse;
import com.ecommerce.user.repository.UserRepository;
import com.ecommerce.user.exception.UserAlreadyExistsException;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class UserService {

    private static final Logger logger = LoggerFactory.getLogger(UserService.class);

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final RoleService roleService;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder, RoleService roleService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.roleService = roleService;
    }

    @Transactional
    public UserResponse registerUser(RegistrationRequest registrationRequest) {
        if (userRepository.existsByEmail(registrationRequest.getEmail())) {
            logger.warn("Attempt to register with already existing email: {}", registrationRequest.getEmail());
            throw new UserAlreadyExistsException("User with email " + registrationRequest.getEmail() + " already exists.");
        }

        User newUser = new User();
        newUser.setName(registrationRequest.getName());
        newUser.setEmail(registrationRequest.getEmail());
        newUser.setPassword(passwordEncoder.encode(registrationRequest.getPassword()));
        
        // Atribuir roles ao usuário
        Set<String> roleNames = registrationRequest.getRoles();
        // Se nenhuma role for especificada, atribui a role padrão USER
        if (roleNames == null || roleNames.isEmpty()) {
            roleNames = new HashSet<>();
            roleNames.add(RoleService.ROLE_USER);
        }
        
        Set<Role> roles = roleService.getRolesByNames(roleNames);
        newUser.setRoles(roles);

        User savedUser = userRepository.save(newUser);
        logger.info("User registered successfully: {}", savedUser.getEmail());

        return new UserResponse(savedUser);
    }

    public User authenticate(String email, String password) {
        return userRepository.findByEmail(email)
                .filter(user -> passwordEncoder.matches(password, user.getPassword()) && user.isActive())
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

    @Transactional
    public User updateUser(String email, User updatedUser) {
        User user = userRepository.findByEmail(email).orElse(null);
        if (user == null) return null;
        user.setName(updatedUser.getName());
        // Não atualizar email nem senha aqui por segurança
        return userRepository.save(user);
    }

    @Transactional
    public boolean deleteByEmail(String email) {
        User user = userRepository.findByEmail(email).orElse(null);
        if (user == null) return false;
        userRepository.delete(user);
        return true;
    }
    
    @Transactional(readOnly = true)
    public List<UserResponse> getAllUsers() {
        return userRepository.findAll().stream()
                .map(UserResponse::new)
                .collect(Collectors.toList());
    }
    
    @Transactional
    public UserResponse updateUserRoles(Long userId, Set<String> roleNames) {
        logger.info("Updating roles for user ID {}: {}", userId, roleNames);
        
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found with id: " + userId));
        
        Set<Role> roles = roleService.getRolesByNames(roleNames);
        logger.info("Found {} roles in the database", roles.size());
        
        user.setRoles(roles);
        
        User savedUser = userRepository.save(user);
        logger.info("User roles updated successfully for user ID {}", userId);
        
        return new UserResponse(savedUser);
    }
    
    @Transactional
    public UserResponse toggleUserActive(Long userId) {
        logger.info("Toggling active status for user ID {}", userId);
        
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found with id: " + userId));
        
        boolean newStatus = !user.isActive();
        user.setActive(newStatus);
        
        User savedUser = userRepository.save(user);
        logger.info("User active status toggled to {} for user ID {}", newStatus, userId);
        
        return new UserResponse(savedUser);
    }
} 