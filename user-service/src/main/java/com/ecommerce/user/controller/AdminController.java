package com.ecommerce.user.controller;

import com.ecommerce.user.model.dto.UserResponse;
import com.ecommerce.user.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Set;

/**
 * Controlador para funções administrativas relacionadas a usuários.
 * Todas as operações requerem permissões administrativas.
 */
@RestController
@RequestMapping("/admin")
@PreAuthorize("hasAuthority('ADMIN_ACCESS')")
public class AdminController {

    private final UserService userService;

    public AdminController(UserService userService) {
        this.userService = userService;
    }

    /**
     * Lista todos os usuários do sistema.
     * Requer permissão ADMIN_ACCESS ou READ_ALL_USERS.
     */
    @GetMapping("/users")
    @PreAuthorize("hasAnyAuthority('ADMIN_ACCESS', 'READ_ALL_USERS')")
    public ResponseEntity<List<UserResponse>> getAllUsers() {
        List<UserResponse> users = userService.getAllUsers();
        return ResponseEntity.ok(users);
    }

    /**
     * Atualiza as roles de um usuário específico.
     * Requer permissão ADMIN_ACCESS.
     */
    @PutMapping("/users/{userId}/roles")
    public ResponseEntity<UserResponse> updateUserRoles(
            @PathVariable Long userId, 
            @RequestBody Set<String> roles) {
        UserResponse updatedUser = userService.updateUserRoles(userId, roles);
        return ResponseEntity.ok(updatedUser);
    }

    /**
     * Ativa ou desativa um usuário.
     * Requer permissão ADMIN_ACCESS.
     */
    @PutMapping("/users/{userId}/toggle-active")
    public ResponseEntity<UserResponse> toggleUserActive(@PathVariable Long userId) {
        UserResponse updatedUser = userService.toggleUserActive(userId);
        return ResponseEntity.ok(updatedUser);
    }
} 