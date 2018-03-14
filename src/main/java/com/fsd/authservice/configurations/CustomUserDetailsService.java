package com.fsd.authservice.configurations;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.ArrayList;

public class CustomUserDetailsService implements UserDetailsService {
    private Logger logger = LoggerFactory.getLogger(this.getClass());
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        logger.info("Username Passed: {}", username);

        if (username == null || username.isEmpty()) {
            throw new UsernameNotFoundException("Username is empty");
        }

        // Need to add more logic here

        return new User(username, "$2a$10$xeQbJg5gGi.e/SRvs0kT0uNN5pLVNFK8um2ZoZnACnCRZSQS5/IrW", new ArrayList<>());

    }
}
