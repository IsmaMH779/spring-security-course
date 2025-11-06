package com.cursos.api.spring_security_course.config.security;

import com.cursos.api.spring_security_course.config.security.filter.JwtAuthenticationFilter;
import com.cursos.api.spring_security_course.persistence.util.RoleEnum;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.RegexRequestMatcher;

@Configuration
@EnableWebSecurity
//@EnableMethodSecurity(prePostEnabled = true)
public class HttpSecurityConfig {

    private AuthenticationProvider daoAuthProvider;
    private JwtAuthenticationFilter jwtAuthenticationFilter;
    private AuthenticationEntryPoint authenticationEntryPoint;
    private AccessDeniedHandler accessDeniedHandler;
    private AuthorizationManager<RequestAuthorizationContext> authorizationManager;

    @Autowired
    public HttpSecurityConfig(AuthenticationProvider daoAuthProvider, JwtAuthenticationFilter jwtAuthenticationFilter, AuthenticationEntryPoint authenticationEntryPoint, AccessDeniedHandler accessDeniedHandler, AuthorizationManager<RequestAuthorizationContext> authorizationManager) {
        this.daoAuthProvider = daoAuthProvider;
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
        this.authenticationEntryPoint = authenticationEntryPoint;
        this.accessDeniedHandler = accessDeniedHandler;
        this.authorizationManager = authorizationManager;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        SecurityFilterChain filterChain = http
                .csrf( csrfConfig -> csrfConfig.disable() )
                .sessionManagement( sessionConfig -> sessionConfig.sessionCreationPolicy(SessionCreationPolicy.STATELESS) )
                .authenticationProvider(daoAuthProvider)
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .authorizeHttpRequests( authReqConfig -> {
                   authReqConfig.anyRequest().access(authorizationManager);
                })
                .exceptionHandling( exceptionConfig -> {
                    exceptionConfig.authenticationEntryPoint(authenticationEntryPoint);
                    exceptionConfig.accessDeniedHandler(accessDeniedHandler);
                })
                .build();

        return filterChain;
    }

    private static void buildRequestMatchers(AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry authReqConfig) {

            /*
            Autorizacion de endpoints de products
             */

            authReqConfig.requestMatchers(HttpMethod.GET, "/products")
                    .hasAnyRole(RoleEnum.ADMINISTRATOR.name(), RoleEnum.ASSISTANT_ADMINISTRATOR.name());

            //authReqConfig.requestMatchers(HttpMethod.GET, "/products/{productId}")
            authReqConfig.requestMatchers(RegexRequestMatcher.regexMatcher(HttpMethod.GET, "/products/[0-9]*"))
                    .hasAnyRole(RoleEnum.ADMINISTRATOR.name(), RoleEnum.ASSISTANT_ADMINISTRATOR.name());

            authReqConfig.requestMatchers(HttpMethod.POST, "/products")
                    .hasRole(RoleEnum.ADMINISTRATOR.name());

            authReqConfig.requestMatchers(HttpMethod.PUT, "/products/{productId}")
                    .hasAnyRole(RoleEnum.ADMINISTRATOR.name(), RoleEnum.ASSISTANT_ADMINISTRATOR.name());

            authReqConfig.requestMatchers(HttpMethod.PUT, "/products/{productId}/disabled")
                    .hasRole(RoleEnum.ADMINISTRATOR.name());

            /*
            Autorizacion de endpoints de categories
             */

            authReqConfig.requestMatchers(HttpMethod.GET, "/categories")
                    .hasAnyRole(RoleEnum.ADMINISTRATOR.name(), RoleEnum.ASSISTANT_ADMINISTRATOR.name());

            authReqConfig.requestMatchers(HttpMethod.GET, "/categories/{categoryId}")
                    .hasAnyRole(RoleEnum.ADMINISTRATOR.name(), RoleEnum.ASSISTANT_ADMINISTRATOR.name());

            authReqConfig.requestMatchers(HttpMethod.POST, "/categories")
                    .hasRole(RoleEnum.ADMINISTRATOR.name());

            authReqConfig.requestMatchers(HttpMethod.PUT, "/categories/{categoryId}")
                    .hasAnyRole(RoleEnum.ADMINISTRATOR.name(), RoleEnum.ASSISTANT_ADMINISTRATOR.name());

            authReqConfig.requestMatchers(HttpMethod.PUT, "/categories/{categoryId}/disabled")
                    .hasRole(RoleEnum.ADMINISTRATOR.name());


            /*
                Autorizacion de endpoints de categories
             */

            authReqConfig.requestMatchers(HttpMethod.GET, "/auth/profile")
                    .hasAnyRole(RoleEnum.ADMINISTRATOR.name(), RoleEnum.ASSISTANT_ADMINISTRATOR.name(), RoleEnum.CUSTOMER.name());

            /*
            Autorizacion de endpoints de publicos
             */

            authReqConfig.requestMatchers(HttpMethod.POST,"/customers").permitAll();
            authReqConfig.requestMatchers(HttpMethod.POST,"/auth/authenticate").permitAll();
            authReqConfig.requestMatchers(HttpMethod.GET,"/auth/validate-token").permitAll();

            // El resto necesita autenticacion
            authReqConfig.anyRequest().authenticated();
    }

    private static void buildRequestMatchersV2(AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry authReqConfig) {
            /*
            Autorizacion de endpoints de publicos
             */

        authReqConfig.requestMatchers(HttpMethod.POST,"/customers").permitAll();
        authReqConfig.requestMatchers(HttpMethod.POST,"/auth/authenticate").permitAll();
        authReqConfig.requestMatchers(HttpMethod.GET,"/auth/validate-token").permitAll();

        // El resto necesita autenticacion
        authReqConfig.anyRequest().authenticated();
    }

}
