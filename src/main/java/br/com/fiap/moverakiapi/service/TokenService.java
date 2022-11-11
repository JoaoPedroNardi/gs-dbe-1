package br.com.fiap.moverakiapi.service;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

import br.com.fiap.moverakiapi.model.Usuario;
import br.com.fiap.moverakiapi.repository.UsuarioRepository;

public class TokenService {

    @Autowired
    UsuarioRepository repository;

    public boolean validate(String token) {

        try{
            JWT.require(Algorithm.HMAC512("palavramagica")).build().verify(token);
            return true;
        }catch(Exception e){
            return false;
        }
    }

    public Authentication getAuthenticationToken(String token) {

        String email = JWT.require(Algorithm.HMAC512("palavramagica")).build().verify(token).getSubject();
        Optional<Usuario> optional = repository.findByEmail(email);

        if(optional.isEmpty()) return null;
        var usuario = optional.get();

        Authentication authentication = 
            new UsernamePasswordAuthenticationToken(usuario, null, usuario.getAuthorities());
                        
        return authentication;
    }

}

