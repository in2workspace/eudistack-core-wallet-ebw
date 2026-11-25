package com.eudistack.ebw.infrastructure.configuration;

import com.eudistack.ebw.domain.model.EmailLanguage;
import com.eudistack.ebw.domain.model.ReactorContextKeys;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

/**
 * Puts in the Reactor context the supported language the request's {@code Accept-Language} prefers (EUD-8
 * AD-10): the Wallet App sends its active language on every call. The code email uses it, and opening a
 * session or registering or binding a Wallet Instance stores it as the language of the account.
 */
@Component
public class RequestLanguageWebFilter implements WebFilter, Ordered {

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE + 2;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        var header = exchange.getRequest().getHeaders().getFirst(HttpHeaders.ACCEPT_LANGUAGE);
        return EmailLanguage.fromAcceptLanguage(header)
                .map(language -> chain.filter(exchange)
                        .contextWrite(ctx -> ctx.put(ReactorContextKeys.REQUEST_LANGUAGE, language)))
                .orElseGet(() -> chain.filter(exchange));
    }
}
