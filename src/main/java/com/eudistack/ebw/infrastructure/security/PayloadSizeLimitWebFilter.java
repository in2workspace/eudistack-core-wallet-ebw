package com.eudistack.ebw.infrastructure.security;

import com.eudistack.ebw.domain.model.exception.PayloadTooLargeException;
import com.eudistack.ebw.infrastructure.adapter.properties.SecurityProperties;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpMethod;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpRequestDecorator;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.ServerWebExchangeDecorator;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;

@Component
public class PayloadSizeLimitWebFilter implements WebFilter, Ordered {

    private static final Set<HttpMethod> METHODS_WITH_BODY = Set.of(HttpMethod.POST, HttpMethod.PUT, HttpMethod.PATCH);

    private final long maxPayloadSize;

    public PayloadSizeLimitWebFilter(SecurityProperties securityProperties) {
        this.maxPayloadSize = securityProperties.maxPayloadSize();
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        var method = exchange.getRequest().getMethod();
        if (!METHODS_WITH_BODY.contains(method)) {
            return chain.filter(exchange);
        }

        // Fast reject via Content-Length header
        var contentLength = exchange.getRequest().getHeaders().getContentLength();
        if (contentLength > maxPayloadSize) {
            return Mono.error(new PayloadTooLargeException(maxPayloadSize));
        }

        // Wrap request to count bytes for chunked transfer encoding
        var countingRequest = new CountingRequestDecorator(exchange.getRequest(), maxPayloadSize);
        var decoratedExchange = new ServerWebExchangeDecorator(exchange) {
            @Override
            public ServerHttpRequest getRequest() {
                return countingRequest;
            }
        };
        return chain.filter(decoratedExchange);
    }

    private static class CountingRequestDecorator extends ServerHttpRequestDecorator {

        private final long maxPayloadSize;

        CountingRequestDecorator(ServerHttpRequest delegate, long maxPayloadSize) {
            super(delegate);
            this.maxPayloadSize = maxPayloadSize;
        }

        @Override
        public Flux<DataBuffer> getBody() {
            var bytesRead = new AtomicLong(0);
            return super.getBody().doOnNext(dataBuffer -> {
                var currentTotal = bytesRead.addAndGet(dataBuffer.readableByteCount());
                if (currentTotal > maxPayloadSize) {
                    throw new PayloadTooLargeException(maxPayloadSize);
                }
            });
        }
    }
}
