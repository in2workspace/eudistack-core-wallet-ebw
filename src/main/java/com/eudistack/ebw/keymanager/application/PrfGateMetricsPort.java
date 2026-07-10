package com.eudistack.ebw.keymanager.application;

public interface PrfGateMetricsPort {
    void recordPass();
    void recordFail();
}
