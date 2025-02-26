package com.example.IAM_Service.repository;

import com.example.IAM_Service.entity.Role;
import com.example.IAM_Service.entity.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(String name);

    @Query("SELECT CASE WHEN COUNT(r) > 0 THEN TRUE ELSE FALSE END " +
            "FROM User u JOIN u.roles r " +
            "WHERE u.email = :email AND r.isRoot = TRUE")
    Boolean isRoot(String email);

    Page<Role> findAll(Pageable pageable);
}
