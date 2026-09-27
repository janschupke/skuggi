package com.helix;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

// Helix Admin — DELIBERATELY MISCONFIGURED Spring Boot practice target.
// Actuator is fully exposed and env/configprops show unmasked values.
@SpringBootApplication
@RestController
public class HelixApplication {

    public static void main(String[] args) {
        SpringApplication.run(HelixApplication.class, args);
    }

    @GetMapping("/")
    public String index() {
        return "Helix Admin portal. Management endpoints under /actuator.";
    }
}
