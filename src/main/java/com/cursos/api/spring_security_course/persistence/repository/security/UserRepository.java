package com.cursos.api.spring_security_course.persistence.repository.security;

import com.cursos.api.spring_security_course.persistence.entity.security.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);
}
