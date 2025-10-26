package com.cursos.api.spring_security_course.controller;

import com.cursos.api.spring_security_course.dto.SaveCategory;
import com.cursos.api.spring_security_course.persistence.entity.Category;
import com.cursos.api.spring_security_course.service.CategoryService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@RestController
@RequestMapping("/categories")
public class CategoryController {

    private CategoryService categoryService;

    @Autowired
    public CategoryController(CategoryService categoryService) {
        this.categoryService = categoryService;
    }

    @PreAuthorize("hasAnyRole('ADMINISTRATOR', 'ASSISTANT_ADMINISTRATOR')")
    @GetMapping
    public ResponseEntity<Page<Category>> findAll (Pageable pageable) {

        Page<Category> categoryPage = categoryService.findAll(pageable);

        if (categoryPage.hasContent()) {
            return ResponseEntity.ok(categoryPage);
        }

        //return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        return ResponseEntity.notFound().build();
    }

    @PreAuthorize("hasAnyRole('ADMINISTRATOR', 'ASSISTANT_ADMINISTRATOR')")
    @GetMapping("/{categoryId}")
    public ResponseEntity<Category> findOneById (@PathVariable Long categoryId) {

        Optional<Category> category = categoryService.findOneById(categoryId);

        if (category.isPresent()) {
            return ResponseEntity.ok(category.get());
        }

        //return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        return ResponseEntity.notFound().build();
    }

    @PreAuthorize("hasRole('ADMINISTRATOR')")
    @PostMapping
    public ResponseEntity<Category> createOne (@RequestBody @Valid SaveCategory saveCategory) {

        Category category = categoryService.createOne(saveCategory);

        return ResponseEntity.status(HttpStatus.CREATED).body(category);
    }

    @PreAuthorize("hasAnyRole('ADMINISTRATOR', 'ASSISTANT_ADMINISTRATOR')")
    @PutMapping("/{categoryId}")
    public ResponseEntity<Category> updateOneById (@PathVariable Long categoryId,
                                                  @RequestBody @Valid SaveCategory saveCategory) {
        Category category = categoryService.updateOneById(categoryId, saveCategory);
        return ResponseEntity.ok(category);
    }

    @PreAuthorize("hasRole('ADMINISTRATOR')")
    @PutMapping("/{categoryId}/disabled")
    public ResponseEntity<Category> diasbleOneById (@PathVariable Long categoryId) {

        Category category = categoryService.diasbleOneById(categoryId);

        return ResponseEntity.ok(category);
    }
}
