package com.eudistack.ebw.infrastructure.configuration.logging;

import ch.qos.logback.classic.spi.IThrowableProxy;
import ch.qos.logback.classic.spi.StackTraceElementProxy;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class MaskedThrowableProxyTest {

    @Test
    void of_NoException_ReturnsNull() {
        assertThat(MaskedThrowableProxy.of(null)).isNull();
    }

    @Test
    void of_ProxyWithoutSuppressedArray_HasNoSuppressed() {
        assertThat(MaskedThrowableProxy.of(mock(IThrowableProxy.class)).getSuppressed()).isEmpty();
    }

    @Test
    void of_Proxy_ForwardsWhatIsNotAMessage() {
        StackTraceElementProxy[] frames = new StackTraceElementProxy[0];
        IThrowableProxy source = mock(IThrowableProxy.class);
        when(source.getClassName()).thenReturn("java.lang.IllegalStateException");
        when(source.getStackTraceElementProxyArray()).thenReturn(frames);
        when(source.getCommonFrames()).thenReturn(7);
        when(source.isCyclic()).thenReturn(true);

        IThrowableProxy proxy = MaskedThrowableProxy.of(source);

        assertThat(proxy.getClassName()).isEqualTo("java.lang.IllegalStateException");
        assertThat(proxy.getStackTraceElementProxyArray()).isSameAs(frames);
        assertThat(proxy.getCommonFrames()).isEqualTo(7);
        assertThat(proxy.isCyclic()).isTrue();
    }
}
