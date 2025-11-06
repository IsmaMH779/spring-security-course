package com.cursos.api.spring_security_course.dto;

import com.cursos.api.spring_security_course.persistence.util.RoleEnum;

import java.io.Serializable;

public class RegisteredUser implements Serializable {

    private Long id;
    private String username;
    private String name;
    private String role;
    private String jwt;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUserName(String userName) {
        this.username = userName;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }

    public String getJwt() {
        return jwt;
    }

    public void setJwt(String jwt) {
        this.jwt = jwt;
    }
}
