package com.eudistack.ebw.infrastructure.configuration;

import io.micrometer.context.ContextRegistry;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import reactor.test.StepVerifier;

class ReactorContextPropagationConfigTest {

    private static final String KEY = "reactor-context-propagation-test";
    private static final ThreadLocal<String> THREAD_LOCAL = new ThreadLocal<>();

    @BeforeEach
    void registerAccessor() {
        ContextRegistry.getInstance().registerThreadLocalAccessor(
                KEY, THREAD_LOCAL::get, THREAD_LOCAL::set, THREAD_LOCAL::remove);
    }

    @AfterEach
    void removeAccessor() {
        ContextRegistry.getInstance().removeThreadLocalAccessor(KEY);
    }

    @Test
    void init_ReactorContextValue_IsVisibleAsThreadLocalInsideAnOperatorOnAnotherThread() {
        new ReactorContextPropagationConfig().init();

        Mono<String> seenInOperator = Mono.just("ignored")
                .publishOn(Schedulers.boundedElastic())
                .map(ignored -> String.valueOf(THREAD_LOCAL.get()))
                .contextWrite(context -> context.put(KEY, "trace-4bf92f35"));

        StepVerifier.create(seenInOperator)
                .expectNext("trace-4bf92f35")
                .verifyComplete();
    }
}
