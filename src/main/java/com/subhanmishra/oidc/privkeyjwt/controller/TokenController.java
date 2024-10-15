package com.subhanmishra.oidc.privkeyjwt.controller;

import com.subhanmishra.oidc.privkeyjwt.service.TokenService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/assertion")
public class TokenController {

    private final TokenService tokenService;

    public TokenController(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    @GetMapping
    public String getAssertionJwt() {
        return tokenService.createToken();
    }
}
