package com.cursos.api.spring_security_course.service.impl;

import com.cursos.api.spring_security_course.dto.SavePermission;
import com.cursos.api.spring_security_course.dto.ShowPermission;
import com.cursos.api.spring_security_course.exception.ObjectNotFoundException;
import com.cursos.api.spring_security_course.persistence.entity.security.GrantedPermission;
import com.cursos.api.spring_security_course.persistence.entity.security.Operation;
import com.cursos.api.spring_security_course.persistence.entity.security.Role;
import com.cursos.api.spring_security_course.persistence.repository.security.GrantedPermissionRepository;
import com.cursos.api.spring_security_course.persistence.repository.security.OperationRepository;
import com.cursos.api.spring_security_course.persistence.repository.security.RoleRepository;
import com.cursos.api.spring_security_course.service.PermissionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class PermissionServiceImpl implements PermissionService {

    private GrantedPermissionRepository grantedPermissionRepository;
    private RoleRepository roleRepository;
    private OperationRepository operationRepository;

    @Autowired
    public PermissionServiceImpl(GrantedPermissionRepository grantedPermissionRepository, RoleRepository roleRepository, OperationRepository operationRepository) {
        this.grantedPermissionRepository = grantedPermissionRepository;
        this.roleRepository = roleRepository;
        this.operationRepository = operationRepository;
    }

    @Override
    public Page<ShowPermission> findAll(Pageable pageable) {

        Page<GrantedPermission> page = grantedPermissionRepository.findAll(pageable);

        return page.map(PermissionServiceImpl::grantedPermissionToShowPermissionDTO);
    }

    @Override
    public Optional<ShowPermission> findOneById(Long permissionId) {
        Optional<GrantedPermission> permission = grantedPermissionRepository.findById(permissionId);
        
        return permission.map(PermissionServiceImpl::grantedPermissionToShowPermissionDTO);
    }

    @Override
    public ShowPermission createOne(SavePermission savePermission) {

        Optional<Role> role = roleRepository.findByName(savePermission.getRole());
        Optional<Operation> operation = operationRepository.findByName(savePermission.getOperation());

        if (role.isEmpty()) throw new ObjectNotFoundException("No existe el Rol en la base de datos.");
        if (operation.isEmpty()) throw new ObjectNotFoundException("No existe la Operación en la base de datos");

        // Build grantedPermission object
        GrantedPermission grantedPermission = new GrantedPermission();
        grantedPermission.setRole(role.get());
        grantedPermission.setOperation(operation.get());

        // save grantedPermission object on DB
        GrantedPermission grantedPermissionOnDB= grantedPermissionRepository.save(grantedPermission);

        // Build show permission
        ShowPermission showPermission = new ShowPermission();
        showPermission.setId(grantedPermissionOnDB.getId());
        showPermission.setRole(grantedPermissionOnDB.getRole().getName());
        showPermission.setOperation(grantedPermissionOnDB.getOperation().getName());
        showPermission.setModule(grantedPermissionOnDB.getOperation().getModule().getName());

        return showPermission;
    }

    @Override
    public ShowPermission deleteOneById(Long permissionId) {

        Optional<GrantedPermission> grantedPermissionOnDB = grantedPermissionRepository.findById(permissionId);

        if (grantedPermissionOnDB.isEmpty()) throw new ObjectNotFoundException("No existen los permisos en la base de datos");

        grantedPermissionRepository.delete(grantedPermissionOnDB.get());

        ShowPermission showPermission = new ShowPermission();
        showPermission.setId(grantedPermissionOnDB.get().getId());
        showPermission.setRole(grantedPermissionOnDB.get().getRole().getName());
        showPermission.setOperation(grantedPermissionOnDB.get().getOperation().getName());
        showPermission.setModule(grantedPermissionOnDB.get().getOperation().getModule().getName());

        return showPermission;
    }

    private static ShowPermission grantedPermissionToShowPermissionDTO(GrantedPermission each) {
        ShowPermission dto = new ShowPermission();
        dto.setId(each.getId());
        dto.setOperation(each.getOperation().getName());
        dto.setModule(each.getOperation().getModule().getName());
        dto.setRole(each.getRole().getName());

        return dto;
    }
}
