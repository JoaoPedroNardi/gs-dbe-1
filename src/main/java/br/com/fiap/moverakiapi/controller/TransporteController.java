package br.com.fiap.moverakiapi.controller;

import java.util.Optional;

import javax.validation.Valid;

import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import br.com.fiap.moverakiapi.model.Transporte;
import br.com.fiap.moverakiapi.service.TransporteService;

@RestController
@RequestMapping("/api/transporte")
public class TransporteController {

    @Autowired
    private TransporteService service;

    @GetMapping
    @Cacheable("transporte")
    public Page<Transporte> index( @PageableDefault(size = 10) Pageable paginacao){

        return service.listAll(paginacao);
    }
    
    @PostMapping
    @CacheEvict(value="transportes", allEntries = true)
    public ResponseEntity<Transporte> create(@RequestBody @Valid Transporte transporte){

        service.save(transporte);
        return ResponseEntity.status(HttpStatus.CREATED).body(transporte);
    }

    @GetMapping("{id}")
    @Cacheable("transporte")
    public ResponseEntity<Transporte> show(@PathVariable Long id){

        return ResponseEntity.of(service.getById(id));
    }

    @DeleteMapping("{id}")
    @CacheEvict(value="transportes", allEntries = true)
    public ResponseEntity<Object> delete(@PathVariable Long id){

        Optional<Transporte> optional = service.getById(id);
        if(optional.isEmpty())
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();

        service.deleteById(id);
        return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
    }

    @PutMapping("{id}")
    @CacheEvict(value="transportes", allEntries = true)
    public ResponseEntity<Transporte> update(@PathVariable Long id, @RequestBody @Valid Transporte novoTransporte){
        
        Optional<Transporte> optional = service.getById(id);
        if (optional.isEmpty()) 
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();

        var transporte = optional.get();
        BeanUtils.copyProperties(novoTransporte, transporte);
        transporte.setId(id);

        service.save(transporte);
        return ResponseEntity.ok(transporte);
    }

}
