package com.eudistack.ebw.support;

import com.nimbusds.jose.jwk.JWKSet;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Minimal tenant Verifier over HTTP for tests: OpenID discovery on
 * {@code /verifier/.well-known/openid-configuration} with a public {@code jwks_uri}, and the JWK
 * Set on {@code /verifier/oidc/jwks}. Counts the JWK Set reads and can be switched off.
 */
public final class FakeVerifierServer implements AutoCloseable {

    private final HttpServer server;
    private final AtomicReference<JWKSet> jwks;
    private final AtomicInteger jwksReads = new AtomicInteger();
    private final AtomicInteger discoveryReads = new AtomicInteger();
    private volatile boolean available = true;

    public FakeVerifierServer(JWKSet initialJwks) {
        this.jwks = new AtomicReference<>(initialJwks);
        try {
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        server.createContext("/verifier/.well-known/openid-configuration", exchange -> {
            discoveryReads.incrementAndGet();
            respond(exchange, "{\"issuer\":\"https://public.example/verifier\","
                    + "\"jwks_uri\":\"https://public.example/verifier/oidc/jwks\"}");
        });
        server.createContext("/verifier/oidc/jwks", exchange -> {
            jwksReads.incrementAndGet();
            respond(exchange, jwks.get().toString());
        });
        server.start();
    }

    /** Internal base URL, as {@code ebw.verifier.internal-url}. */
    public String internalUrl() {
        return "http://127.0.0.1:" + server.getAddress().getPort() + "/verifier";
    }

    public void setJwks(JWKSet keys) {
        jwks.set(keys);
    }

    public void setAvailable(boolean available) {
        this.available = available;
    }

    public int jwksReads() {
        return jwksReads.get();
    }

    /** Requests to the discovery: every attempt to read the JWK Set, also while unavailable. */
    public int discoveryReads() {
        return discoveryReads.get();
    }

    private void respond(HttpExchange exchange, String body) throws IOException {
        var bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(available ? 200 : 503, available ? bytes.length : -1);
        if (available) {
            exchange.getResponseBody().write(bytes);
        }
        exchange.close();
    }

    @Override
    public void close() {
        server.stop(0);
    }
}
