package com.eudistack.ebw.wallet.config.infrastructure.adapter.kms;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsAsyncClient;

import java.net.URI;

/**
 * Spring configuration that exposes the {@link KmsAsyncClient} bean used by
 * {@link KmsEnvelopeEncryptionAdapter}.
 *
 * <h2>Region resolution</h2>
 * Region is read from {@code aws.region} — a property that the AWS SDK v2 auto-resolve chain
 * (environment variable {@code AWS_DEFAULT_REGION}, ECS task metadata, etc.) also honours.
 * No default value is provided: if the property is missing the application context fails fast
 * at boot with a clear {@link org.springframework.beans.factory.BeanCreationException}.
 *
 * <h2>Credential provider</h2>
 * {@link DefaultCredentialsProvider} is used, which checks (in order): environment variables,
 * Java system properties, {@code ~/.aws/credentials}, ECS container credentials (IAM task role),
 * and EC2 instance profile. On ECS Fargate this resolves to the EBW task role, which must have
 * {@code kms:DescribeKey} and {@code kms:Decrypt} on the tenant CMK (AD-S3, Task 18 IaC).
 *
 * <h2>LocalStack support</h2>
 * If property {@code aws.endpoint-override} is set (e.g. {@code http://localhost:4566}), the
 * builder calls {@link KmsAsyncClient.Builder#endpointOverride(URI)} to redirect all KMS calls
 * to the local endpoint. This single property toggles LocalStack-vs-real-AWS without any
 * {@code @ConditionalOnProperty} conditional beans, keeping the configuration unconditional and
 * easy to reason about. Set it in {@code application-test.yaml} or via an environment variable
 * during integration tests (Task 13).
 *
 * <p>The bean name is {@code kmsAsyncClient} (default derived from the method name), which is
 * what {@code OperationalConfigBeans} (Task 9) will reference when wiring
 * {@link KmsEnvelopeEncryptionAdapter}.
 */
@Configuration
public class KmsClientConfig {

    /**
     * AWS region in which the KMS CMKs reside.
     * Corresponds to {@code aws.region} in {@code application.yaml} (no default — fail-fast).
     */
    private final String region;

    /**
     * Optional LocalStack / custom endpoint override.
     * Defaults to {@code null}, which means the real AWS KMS endpoint is used.
     * Set to e.g. {@code http://localhost:4566} in test environments.
     */
    private final String endpointOverride;

    /**
     * @param region           the value of {@code aws.region} — required, no default
     * @param endpointOverride the value of {@code aws.endpoint-override} — optional, defaults to
     *                         {@code null} (no override, real AWS endpoint is used)
     */
    public KmsClientConfig(
            @Value("${aws.region}") String region,
            @Value("${aws.endpoint-override:#{null}}") String endpointOverride) {
        this.region = region;
        this.endpointOverride = endpointOverride;
    }

    /**
     * Constructs and returns an {@link KmsAsyncClient} configured for the project's region and
     * credential chain.
     *
     * <p>The client is a singleton Spring bean; it is thread-safe and intended to be shared
     * across all KMS operations within the JVM. The AWS SDK manages its own internal thread pool
     * and connection pool, so callers should never close this client manually.
     *
     * @return a fully configured {@link KmsAsyncClient}
     */
    @Bean
    public KmsAsyncClient kmsAsyncClient() {
        var builder = KmsAsyncClient.builder()
                .region(Region.of(region))
                .credentialsProvider(DefaultCredentialsProvider.create());
        if (endpointOverride != null) {
            builder.endpointOverride(URI.create(endpointOverride));
        }
        return builder.build();
    }
}
