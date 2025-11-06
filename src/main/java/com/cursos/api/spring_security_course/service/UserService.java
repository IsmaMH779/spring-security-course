package com.cursos.api.spring_security_course.service;

import com.cursos.api.spring_security_course.dto.SaveUser;
import com.cursos.api.spring_security_course.persistence.entity.security.User;

import java.util.Optional;

public interface UserService {

    User registerOneCustomer(SaveUser newUser);

    Optional<User> findOneByUsername(String username);
}
