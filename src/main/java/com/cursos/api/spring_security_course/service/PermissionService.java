package com.cursos.api.spring_security_course.service;

import com.cursos.api.spring_security_course.dto.SavePermission;
import com.cursos.api.spring_security_course.dto.ShowPermission;
import jakarta.validation.Valid;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.util.Optional;

public interface PermissionService {
    Page<ShowPermission> findAll(Pageable pageable);

    Optional<ShowPermission> findOneById(Long permissionId);

    ShowPermission createOne(@Valid SavePermission savePermission);

    ShowPermission deleteOneById(Long permissionId);
}
