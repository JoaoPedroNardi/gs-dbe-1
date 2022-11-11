package br.com.fiap.moverakiapi.service;

import java.util.Optional;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import br.com.fiap.moverakiapi.model.Usuario;
import br.com.fiap.moverakiapi.repository.UsuarioRepository;

@Service
public class UsuarioService {

    @Autowired
    private UsuarioRepository repository;

    public Page<Usuario> listAll(Pageable paginacao){
        return repository.findAll(paginacao);
    }

    public void create(@Valid Usuario usuario) {
        repository.save(usuario);
    }

    public Optional<Usuario> getById(Long id) {
        return repository.findById(id);
    }

    public void delete(Long id) {
        repository.deleteById(id);
    }
    
}
