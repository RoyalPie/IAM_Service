package com.example.IAM_Service.config;

import com.example.IAM_Service.jwt.JwtFilter;
import com.example.IAM_Service.jwt.JwtKeyCloakFilter;
import com.example.IAM_Service.repository.UserRepository;
import com.example.IAM_Service.service.CustomUserDetailsService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import org.springframework.beans.factory.annotation.Value;


@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final UserRepository userRepository;

    private final CustomUserDetailsService userDetailsService;

    private final JwtKeyCloakFilter jwtKeyCloakFilter;

    @Value("${keycloak.enabled}")
    private boolean keycloakEnabled;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        if (keycloakEnabled) {
            return http
                    .csrf(AbstractHttpConfigurer::disable)
                    .authorizeHttpRequests(authorize -> authorize
                            .requestMatchers("/api/auth/**").permitAll()
                            .requestMatchers("/api/test/**").permitAll()
                            .requestMatchers("/error/**").permitAll()
                            .anyRequest().authenticated()
                    )
                    .oauth2ResourceServer(oauth2 -> oauth2
                            .jwt(Customizer.withDefaults())
                    )
                    .oauth2Login(login->login
                            .loginPage("/oauth2/authorization/keycloak")
                            .defaultSuccessUrl("/user/token")
                    )
                    .build();
        } else {
            return http
                    .csrf(AbstractHttpConfigurer::disable)
                    .authorizeHttpRequests(authorize -> authorize
                            .requestMatchers("/api/auth/**").permitAll()
                            .requestMatchers("/api/test/**").permitAll()
                            .requestMatchers("/error/**").permitAll()
                            .anyRequest().authenticated()
                    )
                    .addFilterBefore(new JwtFilter(), UsernamePasswordAuthenticationFilter.class)
                    .build();
        }
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
