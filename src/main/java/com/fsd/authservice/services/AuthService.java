package com.fsd.authservice.services;

import org.springframework.stereotype.Service;

@Service
public interface AuthService {
    boolean isValidUser(String name, String password);
}
