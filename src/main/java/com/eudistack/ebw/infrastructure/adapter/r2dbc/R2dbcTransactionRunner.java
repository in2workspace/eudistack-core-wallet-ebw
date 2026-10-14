package com.eudistack.ebw.infrastructure.adapter.r2dbc;

import com.eudistack.ebw.domain.spi.TransactionRunner;
import org.springframework.stereotype.Component;
import org.springframework.transaction.reactive.TransactionalOperator;
import reactor.core.publisher.Mono;

/** {@link TransactionRunner} with the R2DBC {@link TransactionalOperator} (tenant schema of the request). */
@Component
public class R2dbcTransactionRunner implements TransactionRunner {

    private final TransactionalOperator transactionalOperator;

    public R2dbcTransactionRunner(TransactionalOperator transactionalOperator) {
        this.transactionalOperator = transactionalOperator;
    }

    @Override
    public <T> Mono<T> inTransaction(Mono<T> work) {
        return transactionalOperator.transactional(work);
    }
}
