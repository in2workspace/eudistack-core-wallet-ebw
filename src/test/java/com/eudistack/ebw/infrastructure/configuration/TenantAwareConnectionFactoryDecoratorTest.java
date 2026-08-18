package com.eudistack.ebw.infrastructure.configuration;

import com.eudistack.ebw.domain.model.ReactorContextKeys;
import io.r2dbc.spi.Connection;
import io.r2dbc.spi.ConnectionFactory;
import io.r2dbc.spi.ConnectionFactoryMetadata;
import io.r2dbc.spi.Statement;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.config.BeanPostProcessor;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import reactor.util.context.Context;

import java.io.Closeable;
import java.io.IOException;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

class TenantAwareConnectionFactoryDecoratorTest {

    @Test
    void beanPostProcessor_shouldWrapConnectionFactory() {
        BeanPostProcessor bpp = TenantAwareConnectionFactoryDecorator.tenantAwareConnectionFactoryPostProcessor();
        ConnectionFactory mockCf = mock(ConnectionFactory.class);
        
        Object result = bpp.postProcessAfterInitialization(mockCf, "connectionFactory");
        
        assertTrue(result instanceof TenantAwareConnectionFactoryDecorator.TenantAwareConnectionFactory);
    }

    @Test
    void beanPostProcessor_shouldNotWrapOtherBeans() {
        BeanPostProcessor bpp = TenantAwareConnectionFactoryDecorator.tenantAwareConnectionFactoryPostProcessor();
        Object otherBean = new Object();
        
        Object result = bpp.postProcessAfterInitialization(otherBean, "otherBean");
        
        assertSame(otherBean, result);
    }

    @Test
    void beanPostProcessor_shouldNotWrapConnectionFactoryWithDifferentName() {
        BeanPostProcessor bpp = TenantAwareConnectionFactoryDecorator.tenantAwareConnectionFactoryPostProcessor();
        ConnectionFactory mockCf = mock(ConnectionFactory.class);
        
        Object result = bpp.postProcessAfterInitialization(mockCf, "otherConnectionFactory");
        
        assertSame(mockCf, result);
    }

    @Test
    void create_withTenantInContext_shouldSetSearchPath() {
        ConnectionFactory delegate = mock(ConnectionFactory.class);
        Connection connection = mock(Connection.class);
        Statement statement = mock(Statement.class);
        
        doReturn(Mono.just(connection)).when(delegate).create();
        when(connection.createStatement(anyString())).thenReturn(statement);
        when(statement.execute()).thenReturn(Mono.empty());
        
        TenantAwareConnectionFactoryDecorator.TenantAwareConnectionFactory decorator = 
                new TenantAwareConnectionFactoryDecorator.TenantAwareConnectionFactory(delegate);
        
        StepVerifier.create(Mono.from(decorator.create())
                .contextWrite(Context.of(ReactorContextKeys.TENANT_DOMAIN, "testtenant")))
                .expectNextMatches(c -> c == connection)
                .verifyComplete();
        
        verify(connection).createStatement("SET search_path TO \"testtenant_business_wallet\", public");
    }

    @Test
    void create_withoutTenantInContext_shouldSetPublicSearchPath() {
        ConnectionFactory delegate = mock(ConnectionFactory.class);
        Connection connection = mock(Connection.class);
        Statement statement = mock(Statement.class);
        
        doReturn(Mono.just(connection)).when(delegate).create();
        when(connection.createStatement(anyString())).thenReturn(statement);
        when(statement.execute()).thenReturn(Mono.empty());
        
        TenantAwareConnectionFactoryDecorator.TenantAwareConnectionFactory decorator = 
                new TenantAwareConnectionFactoryDecorator.TenantAwareConnectionFactory(delegate);
        
        StepVerifier.create(decorator.create())
                .expectNextMatches(c -> c == connection)
                .verifyComplete();
        
        verify(connection).createStatement("SET search_path TO public");
    }

    @Test
    void create_withInvalidTenant_shouldThrowException() {
        ConnectionFactory delegate = mock(ConnectionFactory.class);
        Connection connection = mock(Connection.class);
        
        doReturn(Mono.just(connection)).when(delegate).create();
        
        TenantAwareConnectionFactoryDecorator.TenantAwareConnectionFactory decorator = 
                new TenantAwareConnectionFactoryDecorator.TenantAwareConnectionFactory(delegate);
        
        StepVerifier.create(Mono.from(decorator.create())
                .contextWrite(Context.of(ReactorContextKeys.TENANT_DOMAIN, "1invalid")))
                .expectError(IllegalArgumentException.class)
                .verify();
    }

    @Test
    void create_whenSetSearchPathFails_shouldCloseConnectionAndPropagateError() {
        ConnectionFactory delegate = mock(ConnectionFactory.class);
        Connection connection = mock(Connection.class);
        Statement statement = mock(Statement.class);
        RuntimeException error = new RuntimeException("SQL Error");
        
        doReturn(Mono.just(connection)).when(delegate).create();
        when(connection.createStatement(anyString())).thenReturn(statement);
        when(statement.execute()).thenReturn(Mono.error(error));
        when(connection.close()).thenReturn(Mono.empty());
        
        TenantAwareConnectionFactoryDecorator.TenantAwareConnectionFactory decorator = 
                new TenantAwareConnectionFactoryDecorator.TenantAwareConnectionFactory(delegate);
        
        StepVerifier.create(decorator.create())
                .expectErrorMatches(e -> e == error)
                .verify();
        
        verify(connection).close();
    }

    @Test
    void create_whenCloseConnectionFails_shouldPropagateOriginalError() {
        ConnectionFactory delegate = mock(ConnectionFactory.class);
        Connection connection = mock(Connection.class);
        Statement statement = mock(Statement.class);
        RuntimeException originalError = new RuntimeException("SQL Error");
        RuntimeException closeError = new RuntimeException("Close Error");
        
        doReturn(Mono.just(connection)).when(delegate).create();
        when(connection.createStatement(anyString())).thenReturn(statement);
        when(statement.execute()).thenReturn(Mono.error(originalError));
        when(connection.close()).thenReturn(Mono.error(closeError));
        
        TenantAwareConnectionFactoryDecorator.TenantAwareConnectionFactory decorator = 
                new TenantAwareConnectionFactoryDecorator.TenantAwareConnectionFactory(delegate);
        
        StepVerifier.create(decorator.create())
                .expectErrorMatches(e -> e == originalError)
                .verify();
        
        verify(connection).close();
    }

    @Test
    void getMetadata_shouldDelegate() {
        ConnectionFactory delegate = mock(ConnectionFactory.class);
        ConnectionFactoryMetadata metadata = mock(ConnectionFactoryMetadata.class);
        when(delegate.getMetadata()).thenReturn(metadata);
        
        TenantAwareConnectionFactoryDecorator.TenantAwareConnectionFactory decorator = 
                new TenantAwareConnectionFactoryDecorator.TenantAwareConnectionFactory(delegate);
        
        assertSame(metadata, decorator.getMetadata());
    }

    @Test
    void close_shouldCloseDelegateIfCloseable() throws IOException {
        ConnectionFactory delegate = mock(ConnectionFactory.class, withSettings().extraInterfaces(Closeable.class));
        TenantAwareConnectionFactoryDecorator.TenantAwareConnectionFactory decorator = 
                new TenantAwareConnectionFactoryDecorator.TenantAwareConnectionFactory(delegate);
        
        decorator.close();
        
        verify((Closeable) delegate).close();
    }

    @Test
    void close_shouldNotThrowIfDelegateIsNotCloseable() {
        ConnectionFactory delegate = mock(ConnectionFactory.class);
        TenantAwareConnectionFactoryDecorator.TenantAwareConnectionFactory decorator = 
                new TenantAwareConnectionFactoryDecorator.TenantAwareConnectionFactory(delegate);
        
        assertDoesNotThrow(decorator::close);
    }

    @Test
    void close_shouldHandleExceptionFromDelegate() throws IOException {
        ConnectionFactory delegate = mock(ConnectionFactory.class, withSettings().extraInterfaces(Closeable.class));
        doThrow(new IOException("Close failed")).when((Closeable) delegate).close();
        
        TenantAwareConnectionFactoryDecorator.TenantAwareConnectionFactory decorator = 
                new TenantAwareConnectionFactoryDecorator.TenantAwareConnectionFactory(delegate);
        
        assertDoesNotThrow(decorator::close);
    }
}
