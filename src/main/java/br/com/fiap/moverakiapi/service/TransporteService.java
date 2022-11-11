package br.com.fiap.moverakiapi.service;

import java.util.Optional;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import br.com.fiap.moverakiapi.model.Transporte;
import br.com.fiap.moverakiapi.repository.TransporteRepository;

@Service
public class TransporteService {

    @Autowired
    private TransporteRepository repository;

    public Page<Transporte> listAll(Pageable paginacao){
        return repository.findAll(paginacao);
     }
    

    public void save(@Valid Transporte transporte) {
        repository.save(transporte);
    }

    public Optional<Transporte> getById(Long id) {
        return repository.findById(id);
    }

    public void deleteById(Long id) {
        repository.deleteById(id);
    }

}
