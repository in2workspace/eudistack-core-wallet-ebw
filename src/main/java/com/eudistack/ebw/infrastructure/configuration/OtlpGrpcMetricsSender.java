package com.eudistack.ebw.infrastructure.configuration;

import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import io.grpc.Metadata;
import io.grpc.StatusRuntimeException;
import io.grpc.stub.MetadataUtils;
import io.micrometer.registry.otlp.OtlpMetricsSender;
import io.opentelemetry.proto.collector.metrics.v1.ExportMetricsServiceRequest;
import io.opentelemetry.proto.collector.metrics.v1.MetricsServiceGrpc;

import java.net.URI;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

/**
 * Sends the OTLP metrics batch over gRPC: Micrometer's OTLP registry only speaks HTTP, and the
 * OTel Collector is reached on its gRPC port (4317). One plaintext channel per collector address.
 */
public class OtlpGrpcMetricsSender implements OtlpMetricsSender {

    private final Map<String, ManagedChannel> channels = new ConcurrentHashMap<>();

    @Override
    public void send(Request request) throws Exception {
        String address = request.getAddress();
        if (address == null || address.isBlank()) {
            throw new IllegalArgumentException("OTLP gRPC address is required");
        }
        URI uri = URI.create(address);
        String target = uri.getHost() + ":" + uri.getPort();
        ManagedChannel channel = channels.computeIfAbsent(target, t ->
                ManagedChannelBuilder.forTarget(t)
                        .usePlaintext()
                        .build()
        );
        ExportMetricsServiceRequest exportRequest =
                ExportMetricsServiceRequest.parseFrom(request.getMetricsData());
        Metadata metadata = new Metadata();
        for (Map.Entry<String, String> header : request.getHeaders().entrySet()) {
            String key = header.getKey().toLowerCase(Locale.ROOT);
            if (key.endsWith("-bin")) {
                throw new IllegalArgumentException("Binary gRPC metadata not supported: " + header.getKey());
            }
            metadata.put(Metadata.Key.of(key, Metadata.ASCII_STRING_MARSHALLER), header.getValue());
        }
        MetricsServiceGrpc.MetricsServiceBlockingStub stub =
                MetricsServiceGrpc.newBlockingStub(channel)
                        .withDeadlineAfter(5, TimeUnit.SECONDS);

        if (!metadata.keys().isEmpty()) {
            stub = stub.withInterceptors(MetadataUtils.newAttachHeadersInterceptor(metadata));
        }
        try {
            stub.export(exportRequest);
        } catch (StatusRuntimeException e) {
            throw new IllegalStateException("Failed to export metrics via OTLP/gRPC to " + address, e);
        }
    }
}
