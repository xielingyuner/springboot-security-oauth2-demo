package com.example.kafkademo.controller;

import com.example.kafkademo.oauth2.SecurityContextUtil;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class HelloController {
    @GetMapping("/hello")
    public String sayHello(){
        Map<String, Object> claims = SecurityContextUtil.getClaims();
        System.out.println(claims);
        return "Hello";
    }
}
