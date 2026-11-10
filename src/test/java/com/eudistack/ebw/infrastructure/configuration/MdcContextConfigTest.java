package com.eudistack.ebw.infrastructure.configuration;

import com.eudistack.ebw.domain.model.ReactorContextKeys;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;
import reactor.core.publisher.Hooks;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

class MdcContextConfigTest {

    @AfterEach
    void clearMdc() {
        MDC.clear();
    }

    @Test
    void accessor_writesTheReactorContextTenantToTheMdcAndCleansUp() {
        new MdcContextConfig().registerTenantDomainAccessor();
        Hooks.enableAutomaticContextPropagation();

        AtomicReference<String> observed = new AtomicReference<>();
        Mono<Void> pipeline = Mono.fromRunnable(() -> observed.set(MDC.get(ReactorContextKeys.TENANT_DOMAIN)))
                .then()
                .contextWrite(ctx -> ctx.put(ReactorContextKeys.TENANT_DOMAIN, "sandbox"));

        StepVerifier.create(pipeline).verifyComplete();

        assertThat(observed.get()).as("MDC carries the tenant while the operator runs").isEqualTo("sandbox");
        assertThat(MDC.get(ReactorContextKeys.TENANT_DOMAIN)).as("MDC is cleaned afterwards").isNull();
    }
}
