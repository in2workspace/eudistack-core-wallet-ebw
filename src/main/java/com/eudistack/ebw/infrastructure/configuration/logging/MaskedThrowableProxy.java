package com.eudistack.ebw.infrastructure.configuration.logging;

import ch.qos.logback.classic.spi.IThrowableProxy;
import ch.qos.logback.classic.spi.StackTraceElementProxy;

import java.util.Arrays;

/**
 * An exception with its message, its causes and its suppressed exceptions masked. The frames are
 * forwarded unchanged. It is deliberately not a {@code ThrowableProxy}: the OpenTelemetry appender
 * reads the original {@link Throwable} from that class only, and that would export it unmasked.
 */
final class MaskedThrowableProxy implements IThrowableProxy {

    private final IThrowableProxy delegate;
    private final IThrowableProxy cause;
    private final IThrowableProxy[] suppressed;

    private MaskedThrowableProxy(IThrowableProxy delegate) {
        this.delegate = delegate;
        this.cause = of(delegate.getCause());
        IThrowableProxy[] source = delegate.getSuppressed();
        this.suppressed = source == null
                ? new IThrowableProxy[0]
                : Arrays.stream(source).map(MaskedThrowableProxy::of).toArray(IThrowableProxy[]::new);
    }

    // Terminates on a circular cause: logback's proxy already ends the chain at the repeated exception
    static IThrowableProxy of(IThrowableProxy source) {
        return source == null ? null : new MaskedThrowableProxy(source);
    }

    @Override
    public String getMessage() {
        return MaskingPatternLayout.mask(delegate.getMessage());
    }

    @Override
    public String getClassName() {
        return delegate.getClassName();
    }

    @Override
    public StackTraceElementProxy[] getStackTraceElementProxyArray() {
        return delegate.getStackTraceElementProxyArray();
    }

    @Override
    public int getCommonFrames() {
        return delegate.getCommonFrames();
    }

    @Override
    public IThrowableProxy getCause() {
        return cause;
    }

    @Override
    public IThrowableProxy[] getSuppressed() {
        return suppressed.clone();
    }

    @Override
    public boolean isCyclic() {
        return delegate.isCyclic();
    }
}
