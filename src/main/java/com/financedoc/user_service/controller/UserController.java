package com.financedoc.user_service.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RequestMapping("/user")
@RestController
public class UserController {
    @GetMapping("/test")
    public String test(@RequestHeader("X-User-Email") String email) {
        return "User Service Test OK & X-User-Email = "+ email;
    }
}
