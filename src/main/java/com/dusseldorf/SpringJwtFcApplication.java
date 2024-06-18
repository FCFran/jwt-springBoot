package com.dusseldorf;

import com.dusseldorf.Respository.RoleRepository;
import com.dusseldorf.auth.AuthenticationService;
import com.dusseldorf.auth.RegistrationRequest;
import com.dusseldorf.model.Role;
import com.dusseldorf.model.User;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

import java.util.List;

@SpringBootApplication
@EnableJpaAuditing
public class SpringJwtFcApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringJwtFcApplication.class, args);
	}

	@Bean
	public CommandLineRunner commandLineRunner(RoleRepository roleRepository,
										AuthenticationService service
	){
		return args -> {
			if (roleRepository.findByName("USER").isEmpty()){
				roleRepository.save(Role.builder().name("USER").build());
			}

			service.register(RegistrationRequest.builder()
					.firstname("Felipe")
					.lastname("Delgado")
					.email("delgado@gmail.com")
					.password("12345hello")
					.build());

		};
	}

}
