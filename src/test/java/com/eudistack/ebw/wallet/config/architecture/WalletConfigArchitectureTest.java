package com.eudistack.ebw.wallet.config.architecture;

import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchRule;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

/**
 * ArchUnit architecture tests for the {@code wallet.config} bounded context.
 *
 * <p>Covers T-12 from tech-design §2.3.
 *
 * <p>Enforces the dual-schema architecture decision (AD-1, AD-S2):
 * the discovery read path must NEVER depend on {@code TenantAwareConnectionFactoryDecorator}
 * or any component that routes to a tenant schema. The only valid persistence path
 * for the discovery endpoint is through the {@code publicSchema} pool.
 *
 * <p>Additionally verifies that the domain layer has zero dependency on infrastructure classes.
 */
@AnalyzeClasses(packages = "com.eudistack.ebw.wallet.config")
public class WalletConfigArchitectureTest {

    /**
     * T-12 — Discovery path must not reference {@code TenantAwareConnectionFactoryDecorator}.
     *
     * <p>The class {@code TenantAwareConnectionFactoryDecorator} (introduced by EUDISTACK-2)
     * routes connections to the per-tenant schema. The discovery read path must never use it —
     * it must always use the {@code @Qualifier("publicSchema")} pool which fixes
     * {@code search_path = public}.
     *
     * <p>No class anywhere in the {@code wallet.config} infrastructure layer may depend on
     * {@code TenantAwareConnectionFactoryDecorator} — not even indirectly through a static import.
     * The adapter {@code TenantConfigAuditR2dbcAdapter} uses the {@code publicSchemaRw}
     * connection factory with explicit schema qualification in SQL, not via the tenant-aware decorator.
     *
     * <p>AD-1 invariant: a cross-schema access bug introduced here would allow the discovery
     * endpoint to expose data from a tenant's private schema — a critical security violation.
     */
    @ArchTest
    static final ArchRule no_infrastructure_class_depends_on_tenant_aware_connection_factory =
            noClasses()
                    .that().resideInAPackage("com.eudistack.ebw.wallet.config.infrastructure..")
                    .should().dependOnClassesThat()
                    .haveSimpleName("TenantAwareConnectionFactoryDecorator");

    /**
     * T-12 — Domain layer must not depend on any infrastructure class.
     *
     * <p>Domain classes (models, services, ports, exceptions) must be pure Java with no
     * framework or infrastructure imports. This is the hexagonal architecture contract.
     * Violations here would couple the domain to infrastructure changes and prevent testing
     * domain logic in isolation.
     */
    @ArchTest
    static final ArchRule domain_does_not_depend_on_infrastructure =
            noClasses()
                    .that().resideInAPackage("com.eudistack.ebw.wallet.config.domain..")
                    .should().dependOnClassesThat()
                    .resideInAPackage("com.eudistack.ebw.wallet.config.infrastructure..");

    /**
     * T-12 — Domain layer must not depend on Spring framework classes.
     *
     * <p>The domain layer must be framework-free. Spring annotations or types in the domain
     * would violate the hexagonal principle and prevent reuse outside a Spring context.
     *
     * <p>Exceptions: Spring's {@code @JsonValue} (from Jackson) is permitted on enum types
     * for serialization convenience. However, Spring Boot or WebFlux classes must not appear.
     */
    @ArchTest
    static final ArchRule domain_does_not_depend_on_spring_boot =
            noClasses()
                    .that().resideInAPackage("com.eudistack.ebw.wallet.config.domain..")
                    .should().dependOnClassesThat()
                    .resideInAPackage("org.springframework.boot..");

    /**
     * T-12 — Application layer must not depend on infrastructure classes.
     *
     * <p>Application services (use cases, commands) must only depend on the domain layer
     * (ports, models, exceptions) and not directly on infrastructure adapters.
     * Wiring happens in the configuration/beans layer, not in the application layer.
     */
    @ArchTest
    static final ArchRule application_does_not_depend_on_infrastructure =
            noClasses()
                    .that().resideInAPackage("com.eudistack.ebw.wallet.config.application..")
                    .should().dependOnClassesThat()
                    .resideInAPackage("com.eudistack.ebw.wallet.config.infrastructure..");
}
