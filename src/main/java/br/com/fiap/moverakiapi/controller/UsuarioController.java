package br.com.fiap.moverakiapi.controller;

import java.util.Optional;

import javax.validation.Valid;

import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import br.com.fiap.moverakiapi.dto.UsuarioDto;
import br.com.fiap.moverakiapi.model.Usuario;
import br.com.fiap.moverakiapi.service.UsuarioService;

@RestController
@RequestMapping("/api/usuario")
public class UsuarioController {

    @Autowired
    private UsuarioService service;

    @Autowired
    PasswordEncoder passwordEncoder; 

    @GetMapping
    public Page<Usuario> index(@PageableDefault(size = 10) Pageable paginacao){
        return service.listAll(paginacao);
    }

    @PostMapping
    public ResponseEntity<Usuario> create(@RequestBody @Valid Usuario usuario){
        usuario.setSenha(passwordEncoder.encode(usuario.getSenha()));
        service.create(usuario);
        return ResponseEntity.status(HttpStatus.CREATED).body(usuario);
    }

    @GetMapping("{id}")
    public ResponseEntity<UsuarioDto> getById(@PathVariable Long id){
        Optional<Usuario> optional = service.getById(id);

        if (optional.isEmpty()) return ResponseEntity.notFound().build();
        Usuario usuario = optional.get();

        return ResponseEntity.ok(usuario.toDto());
    }

    @DeleteMapping("{id}")
    @CacheEvict(value="usuario", allEntries = true)
    public ResponseEntity<Usuario> deletar(@PathVariable Long id){

        Optional<Usuario> optional = service.getById(id);
        
        if(optional.isEmpty()){ 
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }
        service.delete(id);
        return ResponseEntity.status(HttpStatus.NO_CONTENT).build();

    }

    @PutMapping("{id}")
    public ResponseEntity<Usuario> update(@PathVariable Long id, @RequestBody @Valid Usuario novoUsuario){

        Optional<Usuario> optional = service.getById(id);
        
        if(optional.isEmpty()){
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }

        var usuario = optional.get();
        BeanUtils.copyProperties(novoUsuario, usuario, new String [] {"id", "senha"});

        service.create(usuario);
        return ResponseEntity.ok(usuario);

    }

    
}
