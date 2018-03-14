package com.fsd.authservice.configurations;

import com.fsd.authservice.services.AuthService;
import com.fsd.authservice.services.AuthServiceImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.common.exceptions.UnauthorizedUserException;
import org.springframework.stereotype.Component;

import java.util.ArrayList;

@Component
public class CustomAuthenticationProvider implements AuthenticationProvider {
    private Logger logger = LoggerFactory.getLogger(this.getClass());

    @Autowired
    private AuthService authService;

    @Bean
    AuthService authService(){
        return new AuthServiceImpl();
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String name = authentication.getName();
        String password = authentication.getCredentials().toString();
        logger.info("Name = {}, Password = {}",
                name, password);

        if (authService.isValidUser(name, password)) {
            logger.info("Succesful authentication!");
            return new UsernamePasswordAuthenticationToken(name, password, new ArrayList<>());
        } else {
            logger.info("Login failed!");
            String message = "Username or Password did not match";
            throw new UnauthorizedUserException(message);
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }
}
