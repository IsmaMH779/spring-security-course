package com.cursos.api.spring_security_course.service.impl;

import com.cursos.api.spring_security_course.dto.SaveUser;
import com.cursos.api.spring_security_course.exception.InvalidPasswordException;
import com.cursos.api.spring_security_course.exception.ObjectNotFoundException;
import com.cursos.api.spring_security_course.persistence.entity.security.Role;
import com.cursos.api.spring_security_course.persistence.entity.security.User;
import com.cursos.api.spring_security_course.persistence.repository.security.UserRepository;
import com.cursos.api.spring_security_course.service.RoleService;
import com.cursos.api.spring_security_course.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.Optional;

@Service
public class UserServiceImpl implements UserService {

    private UserRepository userRepository;

    private PasswordEncoder passwordEncoder;

    private RoleService roleService;

    @Autowired
    public UserServiceImpl(UserRepository userRepository, PasswordEncoder passwordEncoder, RoleService roleService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.roleService = roleService;
    }

    @Override
    public User registerOneCustomer(SaveUser newUser) {
        validatePassword(newUser);

        User user = new User();
        user.setName(newUser.getName());
        user.setUsername(newUser.getUsername());
        user.setPassword(passwordEncoder.encode(newUser.getPassword()));

        Role defaultRole = roleService.findDefaultRole()
                .orElseThrow(() -> new ObjectNotFoundException("Role not found. Default Role"));
        user.setRole(defaultRole);

        return userRepository.save(user);
    }

    @Override
    public Optional<User> findOneByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    private void validatePassword(SaveUser newUser) {

        if (!StringUtils.hasText(newUser.getPassword()) || !StringUtils.hasText(newUser.getRepeatedPassword())) {
            throw new InvalidPasswordException("Null password");
        }

        if (!newUser.getPassword().equals(newUser.getRepeatedPassword())) {
            throw new InvalidPasswordException("Passwords don't match");
        }

    }
}
