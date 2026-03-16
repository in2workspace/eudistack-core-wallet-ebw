package com.eudistack.ebw.infrastructure.configuration;

import org.flywaydb.core.Flyway;
import org.springframework.boot.autoconfigure.flyway.FlywayProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties(FlywayProperties.class)
public class FlywayConfig {

    @Bean(initMethod = "migrate")
    public Flyway flyway(FlywayProperties properties) {
        return Flyway.configure()
                .dataSource(properties.getUrl(), properties.getUser(), properties.getPassword())
                .locations("classpath:db/migration")
                .load();
    }
}
