package com.exponent_software.oauth2authorizationserver;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class OAuth2AuthorizationServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(OAuth2AuthorizationServerApplication.class, args);
    }
    //https://springone.io/authorized

    //http://localhost:8080/oauth2/authorize&response-type=code&clientId=client&scope=OPENID&redirectUri=http://localhost:8080/client/authorize&code_challenge=
}
