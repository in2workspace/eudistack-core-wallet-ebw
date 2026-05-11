package com.eudistack.ebw.wallet.config.infrastructure.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration properties for the AWS CloudFront integration.
 *
 * <p>Bound from the {@code ebw.cloudfront} prefix in {@code application.yaml}.
 * The distribution ID is injected via the {@code CLOUDFRONT_DISTRIBUTION_ID}
 * environment variable in ECS.
 */
@ConfigurationProperties(prefix = "ebw.cloudfront")
public record CloudFrontProperties(String distributionId) {
}
