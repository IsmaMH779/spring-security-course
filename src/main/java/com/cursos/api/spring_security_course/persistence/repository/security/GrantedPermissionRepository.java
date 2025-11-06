package com.cursos.api.spring_security_course.persistence.repository.security;

import com.cursos.api.spring_security_course.persistence.entity.security.GrantedPermission;
import org.springframework.data.jpa.repository.JpaRepository;

public interface GrantedPermissionRepository extends JpaRepository<GrantedPermission, Long> {

}
