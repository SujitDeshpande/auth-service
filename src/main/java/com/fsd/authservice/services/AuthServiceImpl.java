package com.fsd.authservice.services;

public class AuthServiceImpl implements AuthService {
    @Override
    public boolean isValidUser(String name, String password) {
        return true;
    }
}
