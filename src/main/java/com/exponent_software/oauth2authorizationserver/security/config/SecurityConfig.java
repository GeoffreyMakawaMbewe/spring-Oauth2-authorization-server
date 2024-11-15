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
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
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
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.LocalTime;
import java.util.List;
import java.util.UUID;


@Configuration
public class SecurityConfig {

    //UserDetailsService Bean
    @Bean
    UserDetailsService userDetailsService(){

        // http://localhost:8080/oauth2/authorize?response_type=code&client_id=client&scope=openid&redirect_uri=https://springone.io/authorized&code_challenge=QYPAZ5NU8yvtlQ9erXrUYR-T5AGCjCF47vN-KsaI2A8&code_challenge_method=S256

        // http://localhost:8080/oauth2/token?client_id=client&redirect_uri=https://springone.io/authorized&grant_type=authorization_code&code=dWlJMGpGlUAPz0sRU1y8suXDyWejo0_B4-WrLP-ks5kSlcdvlGG-u1OxOORvvpm7IMJaC_lMqzTX2Oh6AKHGOb2J4-Hp6PVPvGjLeUQMnWzz6h3Xyy1D0S6czbiTeU8f&code_verifier=qPsH306-ZDDaOE8DFzVn05TkN3ZZoVmI_6x4LsVglQI


        InMemoryUserDetailsManager uds = new InMemoryUserDetailsManager();

        UserDetails user1 = User
                .withUsername("john")
                .password("12345")
                .authorities("user")
                .build();

        uds.createUser(user1);

        return uds;
    }
    //PasswordEncoder Bean
    @Bean
    PasswordEncoder passwordEncoder(){
        return NoOpPasswordEncoder.getInstance();
    }
    //RegisteredClient Bean
    @Bean
    RegisteredClientRepository registeredClientRepository() {

        RegisteredClient RC1 = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("client")
                .clientSecret("secret")
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .redirectUri("https://springone.io/authorized")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
//                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
//                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
//                .clientSettings(
//                        ClientSettings
//                        .builder()
//                        .requireAuthorizationConsent(true)
//                        .build()
//                )
//                .tokenSettings(
//                        TokenSettings
//                                .builder()
//                                .accessTokenFormat(OAuth2TokenFormat.REFERENCE)
//                                .accessTokenTimeToLive(Duration.ofHours(3))
//                        .build())
                .build();

        return new InMemoryRegisteredClientRepository(RC1);
    }
    //SecurityFilterChain Bean for configuring OAuth2
    @Bean
    @Order(1)
    SecurityFilterChain oauth2SecurityFilterChain (HttpSecurity httpSecurity) throws Exception {

        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(httpSecurity);
        httpSecurity.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                        .oidc(Customizer.withDefaults());

        httpSecurity.exceptionHandling(exception -> exception
                .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")));

      return  httpSecurity.build();
    }
    //SecurityFilterChain Bean for OauthServer
    @Bean
    @Order(2)
    SecurityFilterChain oAuthServerSecurityFilterChain(HttpSecurity http) throws Exception {

        http.formLogin(Customizer.withDefaults());
        http.authorizeHttpRequests(r -> r.anyRequest().authenticated());

        return http.build();
    }
    //Authorization server settings bean
    @Bean
    AuthorizationServerSettings authorizationServerSettings(){

        return AuthorizationServerSettings
                .builder()
                .build();
    }
    //JWKSource Bean for creating JWKSet
    @Bean
    JWKSource<SecurityContext> jwkSource() throws NoSuchAlgorithmException {

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        RSAPublicKey  rsaPublicKey  = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();

        RSAKey rsaKey = new RSAKey
                .Builder(rsaPublicKey)
                .keyID(UUID.randomUUID().toString())
                .privateKey(rsaPrivateKey)
                .build();

        JWKSet jwkSet = new JWKSet(rsaKey);

        return new ImmutableJWKSet<>(jwkSet);
    }
}
