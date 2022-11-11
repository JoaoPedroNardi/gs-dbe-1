package br.com.fiap.moverakiapi.controller;

import java.util.Date;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

import br.com.fiap.moverakiapi.model.JwtToken;
import br.com.fiap.moverakiapi.model.Usuario;


@RestController
@RequestMapping("/api/entrar")
public class AutenticacaoController {

    @Autowired
    AuthenticationManager authenticationManager;

    @PostMapping
    public ResponseEntity<Object> auth(@RequestBody Usuario usuario) {

        try{
            Authentication authentication = 
                new UsernamePasswordAuthenticationToken(usuario.getUsername(), usuario.getPassword());

            authenticationManager.authenticate(authentication);

            Date issuedAt = new Date();
            Date expiresAt = new Date(issuedAt.getTime() + 120_000 );
            String token = JWT.create()
                .withSubject(usuario.getEmail())
                .withIssuedAt(issuedAt)
                .withExpiresAt(expiresAt)
                .sign(Algorithm.HMAC512("palavramagica")
            );

            return ResponseEntity.ok(new JwtToken(token, "Bearer"));

        }catch(AuthenticationException e){
            e.printStackTrace();
        }

        return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
    }
    
    
}
