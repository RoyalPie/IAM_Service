package com.example.IAM_Service.repository;

import com.example.IAM_Service.entity.Permission;
import com.example.IAM_Service.entity.Role;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.Set;

@Repository
public interface PermissionRepository extends JpaRepository<Permission, Long> {
    @Query("SELECT DISTINCT CONCAT(p.resource, '.', p.permission) FROM User u " +
            "JOIN u.roles r " +
            "JOIN r.permissions p " +
            "WHERE u.email = :email")
    Set<String> findUserPermissions(@Param("email") String email);

    @Query("SELECT p FROM Permission p WHERE CONCAT(p.resource, '.', p.permission) = :name")
    Optional<Permission> findByName(@Param("name") String name);

    Page<Permission> findAll(Pageable pageable);
}