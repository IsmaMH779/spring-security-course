package com.cursos.api.spring_security_course.service;

import com.cursos.api.spring_security_course.persistence.entity.security.Role;

import java.util.Optional;

public interface RoleService {
    Optional<Role> findDefaultRole();
}
