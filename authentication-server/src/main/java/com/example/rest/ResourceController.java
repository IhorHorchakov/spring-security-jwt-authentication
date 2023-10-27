package com.example.rest;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
public class ResourceController {

    @GetMapping("/home")
    public String homeAdmin(Principal principal) {
        return "Dear " + principal.getName() + ", you have been authorized and got 'HOME' page";
    }
}
