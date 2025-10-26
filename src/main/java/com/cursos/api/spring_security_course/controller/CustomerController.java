package com.cursos.api.spring_security_course.controller;

import com.cursos.api.spring_security_course.dto.RegisteredUser;
import com.cursos.api.spring_security_course.dto.SaveUser;
import com.cursos.api.spring_security_course.persistence.entity.User;
import com.cursos.api.spring_security_course.service.auth.AuthenticationService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("/customers")
public class CustomerController {

    private AuthenticationService authenticationService;

    @Autowired
    public CustomerController(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    @PreAuthorize("permitAll")
    @PostMapping
    public ResponseEntity<RegisteredUser> registerOne(@RequestBody @Valid SaveUser newUser) {

        RegisteredUser registeredUser = authenticationService.registerOneCustomer(newUser);

        return ResponseEntity.status(HttpStatus.CREATED).body(registeredUser);
    }

    // End point para testear los permisos
    @PreAuthorize("denyAll")
    @GetMapping
    public ResponseEntity<List<User>> findAll() {
        return ResponseEntity.ok(Arrays.asList());
    }
}
