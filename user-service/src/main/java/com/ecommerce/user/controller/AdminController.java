package com.ecommerce.user.controller;

import com.ecommerce.user.model.dto.UserResponse;
import com.ecommerce.user.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.GrantedAuthority;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Controlador para funções administrativas relacionadas a usuários.
 * Todas as operações requerem permissões administrativas.
 */
@RestController
@RequestMapping("/admin")
@PreAuthorize("hasRole('ADMIN')")
public class AdminController {
    private static final Logger logger = LoggerFactory.getLogger(AdminController.class);

    private final UserService userService;

    public AdminController(UserService userService) {
        this.userService = userService;
    }

    /**
     * Lista todos os usuários do sistema.
     * Requer role ADMIN ou permissão READ_ALL_USERS.
     */
    @GetMapping("/users")
    @PreAuthorize("hasRole('ADMIN') or hasAuthority('READ_ALL_USERS')")
    public ResponseEntity<List<UserResponse>> getAllUsers() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        logAuthDetails(auth, "getAllUsers");
        List<UserResponse> users = userService.getAllUsers();
        return ResponseEntity.ok(users);
    }

    /**
     * Atualiza as roles de um usuário específico.
     * Requer role ADMIN.
     */
    @PutMapping("/users/{userId}/roles")
    public ResponseEntity<UserResponse> updateUserRoles(
            @PathVariable Long userId, 
            @RequestBody Set<String> roles) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        logAuthDetails(auth, "updateUserRoles");
        UserResponse updatedUser = userService.updateUserRoles(userId, roles);
        return ResponseEntity.ok(updatedUser);
    }

    /**
     * Ativa ou desativa um usuário.
     * Requer role ADMIN.
     */
    @PutMapping("/users/{userId}/toggle-active")
    public ResponseEntity<UserResponse> toggleUserActive(@PathVariable Long userId) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        logAuthDetails(auth, "toggleUserActive");
        UserResponse updatedUser = userService.toggleUserActive(userId);
        return ResponseEntity.ok(updatedUser);
    }
    
    private void logAuthDetails(Authentication auth, String methodName) {
        if (auth != null) {
            String principal = auth.getPrincipal().toString();
            List<String> authorities = auth.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toList());
            
            logger.info("Method: {}, Principal: {}, Authenticated: {}, Authorities: {}", 
                    methodName, principal, auth.isAuthenticated(), authorities);
        } else {
            logger.warn("Method: {}, No authentication found", methodName);
        }
    }
} 