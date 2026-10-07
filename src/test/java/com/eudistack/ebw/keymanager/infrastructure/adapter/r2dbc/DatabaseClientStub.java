package com.eudistack.ebw.keymanager.infrastructure.adapter.r2dbc;

import io.r2dbc.spi.Row;
import io.r2dbc.spi.RowMetadata;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.r2dbc.core.DatabaseClient.GenericExecuteSpec;
import org.springframework.r2dbc.core.FetchSpec;
import org.springframework.r2dbc.core.RowsFetchSpec;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BiFunction;
import java.util.function.Function;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Mockito-backed stand-in for the fluent {@link DatabaseClient} API used by the raw-SQL adapters. It records the
 * executed SQL and the bound parameters, and runs the adapter's own row mapper against {@link #row} so the
 * mapping code is exercised without a database.
 */
@SuppressWarnings("unchecked")
final class DatabaseClientStub {

    final DatabaseClient client = mock(DatabaseClient.class);
    final Row row = mock(Row.class);
    final List<String> executedSql = new ArrayList<>();
    final Map<String, Object> bindings = new LinkedHashMap<>();

    /** When {@code false}, {@code .one()} completes empty (no row returned). */
    boolean rowPresent = true;
    /** Result of {@code .fetch().rowsUpdated()}; replace with {@code Mono.error(...)} to simulate a failure. */
    Mono<Long> rowsUpdated = Mono.just(1L);

    DatabaseClientStub() {
        var spec = mock(GenericExecuteSpec.class);
        var metadata = mock(RowMetadata.class);
        FetchSpec<Map<String, Object>> fetchSpec = mock(FetchSpec.class);

        when(client.sql(anyString())).thenAnswer(inv -> {
            executedSql.add(inv.getArgument(0));
            return spec;
        });
        when(spec.bind(anyString(), any())).thenAnswer(inv -> {
            bindings.put(inv.getArgument(0), inv.getArgument(1));
            return spec;
        });
        when(spec.bindNull(anyString(), any())).thenAnswer(inv -> {
            bindings.put(inv.getArgument(0), null);
            return spec;
        });
        when(spec.map(any(Function.class))).thenAnswer(inv ->
                rowsFetchSpec(r -> ((Function<Row, Object>) inv.getArgument(0)).apply(r)));
        when(spec.map(any(BiFunction.class))).thenAnswer(inv ->
                rowsFetchSpec(r -> ((BiFunction<Row, RowMetadata, Object>) inv.getArgument(0)).apply(r, metadata)));
        when(spec.fetch()).thenReturn(fetchSpec);
        when(fetchSpec.rowsUpdated()).thenAnswer(inv -> rowsUpdated);
    }

    private RowsFetchSpec<Object> rowsFetchSpec(Function<Row, Object> mapper) {
        RowsFetchSpec<Object> rowsFetchSpec = mock(RowsFetchSpec.class);
        when(rowsFetchSpec.one()).thenAnswer(inv ->
                rowPresent ? Mono.fromCallable(() -> mapper.apply(row)) : Mono.empty());
        return rowsFetchSpec;
    }
}
