package com.financedoc.user_service.auth.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RequestMapping("/user")
@RestController
public class UserTestController {

    @GetMapping("/test")
    public String test(
            @RequestHeader(value = "X-User-Email", required = false) String email
    ){
        if (email == null) {
            email = "null token"; // 기본값
        }

        return "User Service Test OK & X-User-Email = "+email;
    }

}