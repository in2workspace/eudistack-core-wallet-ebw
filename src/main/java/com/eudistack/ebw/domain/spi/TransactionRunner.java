package com.eudistack.ebw.domain.spi;

import reactor.core.publisher.Mono;

/** Runs a reactive unit of work in one database transaction: all of it is stored or none. */
public interface TransactionRunner {

    <T> Mono<T> inTransaction(Mono<T> work);
}
