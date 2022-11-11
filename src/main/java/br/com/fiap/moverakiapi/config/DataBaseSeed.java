package br.com.fiap.moverakiapi.config;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.crypto.password.PasswordEncoder;

import br.com.fiap.moverakiapi.model.Transporte;
import br.com.fiap.moverakiapi.model.Usuario;
import br.com.fiap.moverakiapi.repository.TransporteRepository;
import br.com.fiap.moverakiapi.repository.UsuarioRepository;

@Configuration
@Profile("desenvolvimento")
public class DataBaseSeed implements CommandLineRunner{

    @Autowired
    TransporteRepository transpRepository;

    @Autowired
    UsuarioRepository usuarioRepository;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) throws Exception {

        transpRepository.saveAll(List.of(
            new Transporte("E198","Praça Sant'Ana", "Terminal Estudantes"),
            new Transporte("E212","Shopping LaVille", "Terminal Estudantes"),
            new Transporte("C02","Catedral Santo André", "Centro"),
            new Transporte("C03","Praça dos Imigrantes", "Centro"),
            new Transporte("C04","Ipiranga", "Centro")

        ));

        usuarioRepository.saveAll(List.of(

            new Usuario()
                .nome("Tiago")
                .email("tiago@gmail.com")
                .senha(passwordEncoder.encode("trm436@rmt")),
            new Usuario()
                .nome("Pedro")
                .email("pedro@fiap.com.br")
                .senha(passwordEncoder.encode("ppplm@67")),
            new Usuario()
                .nome("Luiza")
                .email("luizaml@gmail.com")
                .senha(passwordEncoder.encode("08092001@gh")),
            new Usuario()
                .nome("Tereza")
                .email("tgoncalves@fiap.com.br")
                .senha(passwordEncoder.encode("tigoq54@")),
            new Usuario()
                .nome("Paula")
                .email("paula@gmail.com")
                .senha(passwordEncoder.encode("mypassword@1234")) 

        ));
        
    }
    
}
