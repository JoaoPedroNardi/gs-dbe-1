package br.com.fiap.moverakiapi.model;

import java.util.Collection;
import java.util.List;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.ManyToMany;
import javax.persistence.Table;
import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.Assert;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonProperty.Access;

import br.com.fiap.moverakiapi.dto.UsuarioDto;


@Entity
@Table(name="tab_mvrk_usuario")
public class Usuario implements UserDetails{

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank @Column(name="nome",length = 100,nullable=false)
    private String nome;

    @Email @Column(name="email",length = 255,nullable=false)
    private String email;

    @Size(min=8) @Column(name="senha",length = 300,nullable=false)
    @JsonProperty(access = Access.WRITE_ONLY)
    private String senha;
    
    @ManyToMany(fetch = FetchType.EAGER)
    private List<Atribuicao> atribuicoes;

    public UsuarioDto toDto(){
        return new UsuarioDto(id, nome, email);
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getNome() {
        return nome;
    }

    public void setNome(String nome) {
        this.nome = nome;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getSenha() {
        return senha;
    }

    public void setSenha(String senha) {
        this.senha = senha;
    }

    public Usuario nome(String nome){
        Assert.notNull(nome, "nome é obrigatório");
        this.nome = nome;
        return this;
    }

    public Usuario email(String email){
        Assert.notNull(email, "email é obrigatório");
        this.email = email;
        return this;
    }

    public Usuario senha(String senha){
        Assert.notNull(senha, "senha é obrigatório");
        this.senha = senha;
        return this;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.atribuicoes;
    }

    @JsonIgnore
    @Override
    public String getPassword() {
        return this.senha;
    }

    @Override
    public String getUsername() {
        return this.email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
