package com.eudistack.ebw.infrastructure.configuration;

import io.grpc.Metadata;
import io.grpc.Server;
import io.grpc.ServerCall;
import io.grpc.ServerCallHandler;
import io.grpc.ServerInterceptor;
import io.grpc.ServerInterceptors;
import io.grpc.Status;
import io.grpc.netty.shaded.io.grpc.netty.NettyServerBuilder;
import io.grpc.stub.StreamObserver;
import io.micrometer.registry.otlp.OtlpMetricsSender.Request;
import io.opentelemetry.proto.collector.metrics.v1.ExportMetricsServiceRequest;
import io.opentelemetry.proto.collector.metrics.v1.ExportMetricsServiceResponse;
import io.opentelemetry.proto.collector.metrics.v1.MetricsServiceGrpc;
import io.opentelemetry.proto.metrics.v1.ResourceMetrics;
import io.opentelemetry.proto.resource.v1.Resource;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class OtlpGrpcMetricsSenderTest {

    private static final Metadata.Key<String> TENANT_HEADER =
            Metadata.Key.of("x-tenant", Metadata.ASCII_STRING_MARSHALLER);

    private final AtomicReference<ExportMetricsServiceRequest> received = new AtomicReference<>();
    private final AtomicReference<Metadata> receivedHeaders = new AtomicReference<>();
    private final AtomicReference<Status> replyStatus = new AtomicReference<>(Status.OK);

    private Server collector;
    private final OtlpGrpcMetricsSender sender = new OtlpGrpcMetricsSender();

    @BeforeEach
    void startCollector() throws Exception {
        MetricsServiceGrpc.MetricsServiceImplBase service = new MetricsServiceGrpc.MetricsServiceImplBase() {
            @Override
            public void export(ExportMetricsServiceRequest request,
                               StreamObserver<ExportMetricsServiceResponse> responseObserver) {
                received.set(request);
                if (replyStatus.get().isOk()) {
                    responseObserver.onNext(ExportMetricsServiceResponse.getDefaultInstance());
                    responseObserver.onCompleted();
                } else {
                    responseObserver.onError(replyStatus.get().asRuntimeException());
                }
            }
        };
        collector = NettyServerBuilder.forPort(0)
                .addService(ServerInterceptors.intercept(service, new ServerInterceptor() {
                    @Override
                    public <Q, R> ServerCall.Listener<Q> interceptCall(
                            ServerCall<Q, R> call, Metadata headers, ServerCallHandler<Q, R> next) {
                        receivedHeaders.set(headers);
                        return next.startCall(call, headers);
                    }
                }))
                .build()
                .start();
    }

    @AfterEach
    void stopCollector() {
        collector.shutdownNow();
    }

    @Test
    void send_ValidBatch_ExportsItToTheCollectorWithItsHeaders() throws Exception {
        ExportMetricsServiceRequest batch = batch();

        sender.send(Request.builder(batch.toByteArray())
                .address(collectorAddress())
                .headers(Map.of("X-Tenant", "sandbox"))
                .build());

        assertThat(received.get()).isEqualTo(batch);
        assertThat(receivedHeaders.get().get(TENANT_HEADER)).isEqualTo("sandbox");
    }

    @Test
    void send_CollectorRejectsTheBatch_ThrowsIllegalStateWithTheAddress() {
        replyStatus.set(Status.UNAVAILABLE);
        Request request = Request.builder(batch().toByteArray())
                .address(collectorAddress())
                .headers(Map.of())
                .build();

        assertThatThrownBy(() -> sender.send(request))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining(collectorAddress());
    }

    @Test
    void send_BlankAddress_ThrowsIllegalArgument() {
        Request request = Request.builder(batch().toByteArray()).address(" ").headers(Map.of()).build();

        assertThatThrownBy(() -> sender.send(request)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void send_BinaryHeader_ThrowsIllegalArgumentWithoutExporting() {
        Request request = Request.builder(batch().toByteArray())
                .address(collectorAddress())
                .headers(Map.of("Trace-Bin", "AAEC"))
                .build();

        assertThatThrownBy(() -> sender.send(request)).isInstanceOf(IllegalArgumentException.class);
        assertThat(received.get()).isNull();
    }

    private String collectorAddress() {
        return "http://127.0.0.1:" + collector.getPort();
    }

    private static ExportMetricsServiceRequest batch() {
        return ExportMetricsServiceRequest.newBuilder()
                .addResourceMetrics(ResourceMetrics.newBuilder().setResource(Resource.getDefaultInstance()))
                .build();
    }
}
