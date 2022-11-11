package br.com.fiap.moverakiapi;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cache.annotation.EnableCaching;

@SpringBootApplication
@EnableCaching
public class MoverakiapiApplication {

	public static void main(String[] args) {
		SpringApplication.run(MoverakiapiApplication.class, args);
	}

}
