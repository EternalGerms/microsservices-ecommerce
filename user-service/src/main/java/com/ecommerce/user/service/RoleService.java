package com.ecommerce.user.service;

import com.ecommerce.user.model.Permission;
import com.ecommerce.user.model.Role;
import com.ecommerce.user.repository.PermissionRepository;
import com.ecommerce.user.repository.RoleRepository;
import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

@Service
public class RoleService {

    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;

    // Constantes para os nomes de roles
    public static final String ROLE_ADMIN = "ROLE_ADMIN";
    public static final String ROLE_USER = "ROLE_USER";
    public static final String ROLE_MANAGER = "ROLE_MANAGER";

    // Constantes para os nomes de permissões
    public static final String PERM_READ_USER = "READ_USER";
    public static final String PERM_WRITE_USER = "WRITE_USER";
    public static final String PERM_DELETE_USER = "DELETE_USER";
    public static final String PERM_READ_ALL_USERS = "READ_ALL_USERS";
    public static final String PERM_ADMIN_ACCESS = "ADMIN_ACCESS";

    public RoleService(RoleRepository roleRepository, PermissionRepository permissionRepository) {
        this.roleRepository = roleRepository;
        this.permissionRepository = permissionRepository;
    }

    @PostConstruct
    @Transactional
    public void initRolesAndPermissions() {
        // Criar permissões padrão se não existirem
        createPermissionIfNotExists(PERM_READ_USER, "Permission to read user details");
        createPermissionIfNotExists(PERM_WRITE_USER, "Permission to create/update user");
        createPermissionIfNotExists(PERM_DELETE_USER, "Permission to delete user");
        createPermissionIfNotExists(PERM_READ_ALL_USERS, "Permission to read all users");
        createPermissionIfNotExists(PERM_ADMIN_ACCESS, "Permission for admin access");

        // Criar e configurar role USER
        Role userRole = createRoleIfNotExists(ROLE_USER, "Regular user role");
        if (userRole != null) {
            Set<Permission> userPermissions = new HashSet<>(Arrays.asList(
                getPermissionByName(PERM_READ_USER),
                getPermissionByName(PERM_WRITE_USER),
                getPermissionByName(PERM_DELETE_USER)
            ));
            userRole.setPermissions(userPermissions);
            roleRepository.save(userRole);
        }

        // Criar e configurar role MANAGER
        Role managerRole = createRoleIfNotExists(ROLE_MANAGER, "Manager role");
        if (managerRole != null) {
            Set<Permission> managerPermissions = new HashSet<>(Arrays.asList(
                getPermissionByName(PERM_READ_USER),
                getPermissionByName(PERM_WRITE_USER),
                getPermissionByName(PERM_READ_ALL_USERS)
            ));
            managerRole.setPermissions(managerPermissions);
            roleRepository.save(managerRole);
        }

        // Criar e configurar role ADMIN
        Role adminRole = createRoleIfNotExists(ROLE_ADMIN, "Administrator role");
        if (adminRole != null) {
            Set<Permission> adminPermissions = new HashSet<>(Arrays.asList(
                getPermissionByName(PERM_READ_USER),
                getPermissionByName(PERM_WRITE_USER),
                getPermissionByName(PERM_DELETE_USER),
                getPermissionByName(PERM_READ_ALL_USERS),
                getPermissionByName(PERM_ADMIN_ACCESS)
            ));
            adminRole.setPermissions(adminPermissions);
            roleRepository.save(adminRole);
        }
    }

    @Transactional(readOnly = true)
    public Role getRoleByName(String name) {
        return roleRepository.findByName(name)
                .orElseThrow(() -> new RuntimeException("Role not found: " + name));
    }

    @Transactional(readOnly = true)
    public Set<Role> getRolesByNames(Set<String> roleNames) {
        Set<Role> roles = new HashSet<>();
        for (String name : roleNames) {
            roleRepository.findByName(name).ifPresent(roles::add);
        }
        return roles;
    }

    private Permission getPermissionByName(String name) {
        return permissionRepository.findByName(name)
                .orElseThrow(() -> new RuntimeException("Permission not found: " + name));
    }

    private Role createRoleIfNotExists(String name, String description) {
        Optional<Role> existingRole = roleRepository.findByName(name);
        if (existingRole.isPresent()) {
            return null; // Role já existe, não precisa criar
        }
        Role role = new Role(name, description);
        return roleRepository.save(role);
    }

    private Permission createPermissionIfNotExists(String name, String description) {
        Optional<Permission> existingPermission = permissionRepository.findByName(name);
        if (existingPermission.isPresent()) {
            return existingPermission.get();
        }
        Permission permission = new Permission(name, description);
        return permissionRepository.save(permission);
    }
} 