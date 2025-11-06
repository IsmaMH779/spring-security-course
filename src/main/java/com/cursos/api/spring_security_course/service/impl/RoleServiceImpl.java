package com.cursos.api.spring_security_course.service.impl;

import com.cursos.api.spring_security_course.persistence.entity.security.Role;
import com.cursos.api.spring_security_course.persistence.repository.security.RoleRepository;
import com.cursos.api.spring_security_course.service.RoleService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class RoleServiceImpl implements RoleService {

    private RoleRepository roleRepository;

    @Value("${security.default.role}")
    private String defaultRole;

    @Autowired
    public RoleServiceImpl(RoleRepository roleRepository) {
        this.roleRepository = roleRepository;
    }

    @Override
    public Optional<Role> findDefaultRole() {
        return roleRepository.findByName(defaultRole);
    }
}
