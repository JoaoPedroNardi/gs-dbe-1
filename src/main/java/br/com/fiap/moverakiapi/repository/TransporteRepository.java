package br.com.fiap.moverakiapi.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import br.com.fiap.moverakiapi.model.Transporte;

public interface TransporteRepository extends JpaRepository<Transporte, Long>{
    
}
