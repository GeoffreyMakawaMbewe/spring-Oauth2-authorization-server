package com.exponent_software.oauth2authorizationserver.security.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

@Configuration
public class SecurityConfig {

    @Bean
    public UserDetailsService userDetailsService(){

        InMemoryUserDetailsManager uds = new InMemoryUserDetailsManager();

        var user1 = User
                .withUsername("john")
                .password(passwordEncoder().encode("12345"))
                .authorities("read")
                .build();

        var user2 = User
                .withUsername("bill")
                .password(passwordEncoder().encode("12345"))
                .authorities("read")
                .build();

        uds.createUser(user1);
        uds.createUser(user2);

        return uds;
    }

    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder(12);
    }

    @Bean
    @Order(1)
    public SecurityFilterChain asSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {

        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(httpSecurity);

        httpSecurity.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(Customizer.withDefaults());

        httpSecurity.exceptionHandling(exception -> exception.authenticationEntryPoint(
              new LoginUrlAuthenticationEntryPoint("/login")
        ) );

       return httpSecurity.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain appSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {

        httpSecurity.formLogin(Customizer.withDefaults());

        httpSecurity.authorizeHttpRequests(request -> request
                .anyRequest()
                .authenticated());

       return httpSecurity.build();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository(){

        RegisteredClient rc1 = RegisteredClient
                .withId(UUID.randomUUID().toString())
                .clientId("secret")
                .clientSecret("secret")
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.EMAIL)
                .redirectUri("https://springone.io/authorized")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .build();

        return new InMemoryRegisteredClientRepository(rc1);
    }
    @Bean
    public AuthorizationServerSettings authorizationServerSettings(){

        return AuthorizationServerSettings
                .builder()
                .build();
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() throws NoSuchAlgorithmException {

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);

        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();

        RSAKey rsaKey = new RSAKey
                .Builder(rsaPublicKey)
                .privateKey(rsaPrivateKey)
                .keyID(UUID.randomUUID().toString())
                .build();

        JWKSet jwkSet = new JWKSet(rsaKey);

        return new ImmutableJWKSet<>(jwkSet);
    }

}
