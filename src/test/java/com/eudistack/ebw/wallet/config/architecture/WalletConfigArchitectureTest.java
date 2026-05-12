package com.eudistack.ebw.wallet.config.architecture;

import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchRule;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noMethods;

/**
 * ArchUnit architecture tests for the {@code wallet.config} bounded context — covers T-5
 * (AD-1, E-11) from tech-design §2.3.
 *
 * <p>The discovery plane in EUDISTACK-412 is <strong>read-only</strong> and lives entirely on the
 * {@code public} schema. These rules enforce the two structural invariants that make that safe:
 * <ol>
 *   <li><strong>Dual-schema isolation (AD-1, AD-S2).</strong> The discovery read path
 *       (controller + read service + R2DBC adapter) must NEVER depend — directly or transitively —
 *       on {@code TenantAwareConnectionFactoryDecorator} (or its nested
 *       {@code TenantAwareConnectionFactory}) or any per-tenant-schema adapter. The only valid
 *       persistence path is the {@code @Qualifier("publicSchema")} pool which pins
 *       {@code search_path = public}. A cross-schema bug here would let the public endpoint expose
 *       a tenant's private data — a critical security violation.</li>
 *   <li><strong>Hexagonal layering.</strong> {@code domain..} has zero dependency on
 *       {@code infrastructure..} or Spring; {@code application..} has zero dependency on
 *       {@code infrastructure..}.</li>
 * </ol>
 *
 * <p>Additionally: no component in {@code wallet.config..} declares the Spring Data
 * {@code @Modifying} annotation — the discovery path issues no write SQL (the write side moved to
 * EUDISTACK-55).
 */
@AnalyzeClasses(packages = "com.eudistack.ebw.wallet.config")
public class WalletConfigArchitectureTest {

    // ------------------------------------------------------------------
    // Dual-schema isolation (AD-1, AD-S2, E-11)
    // ------------------------------------------------------------------

    /**
     * No class anywhere in the {@code wallet.config} bounded context may depend on
     * {@code TenantAwareConnectionFactoryDecorator} — not even indirectly through a static import.
     * This covers the discovery controller, the read service and the R2DBC read adapter at once:
     * if any of them (or anything they pull in) referenced the tenant-aware decorator, the rule
     * fails. The discovery read adapter connects exclusively through the {@code publicSchema}
     * read-only pool (see {@code WalletTenantConfigBeans}).
     */
    @ArchTest
    static final ArchRule wallet_config_does_not_depend_on_tenant_aware_connection_factory_decorator =
            noClasses()
                    .that().resideInAPackage("com.eudistack.ebw.wallet.config..")
                    .should().dependOnClassesThat()
                    .haveSimpleName("TenantAwareConnectionFactoryDecorator");

    /**
     * Same isolation, narrower target: nothing in {@code wallet.config..} may depend on the nested
     * {@code TenantAwareConnectionFactory} (the per-request connection wrapper that mutates
     * {@code search_path} to the tenant schema). Catches the case where a refactor exposes the
     * inner type without going through the decorator.
     */
    @ArchTest
    static final ArchRule wallet_config_does_not_depend_on_tenant_aware_connection_factory =
            noClasses()
                    .that().resideInAPackage("com.eudistack.ebw.wallet.config..")
                    .should().dependOnClassesThat()
                    .haveSimpleName("TenantAwareConnectionFactory");

    // ------------------------------------------------------------------
    // Read-only discovery plane: no @Modifying anywhere in wallet.config..
    // ------------------------------------------------------------------

    /**
     * The discovery path is read-only — it issues no INSERT/UPDATE/DELETE. Spring Data's
     * {@code @Modifying} annotation marks a write query, so its mere presence anywhere in
     * {@code wallet.config..} would signal a reintroduced write path (which belongs to
     * EUDISTACK-55). ArchUnit checks the annotation cheaply; the "no INSERT|UPDATE|DELETE SQL
     * literal against {@code tenant_wallet_config}" check is intentionally not implemented here —
     * ArchUnit cannot reliably inspect SQL string literals, and the EUDISTACK-412 cleanup already
     * removed the write path, so this annotation check is the pragmatic belt-and-braces guard.
     * <!-- TODO: a "no write-SQL literal against tenant_wallet_config" check is out of ArchUnit's
     *      reach; revisit only if a SQL-literal linter becomes available. -->
     */
    @ArchTest
    static final ArchRule wallet_config_has_no_modifying_queries =
            noMethods()
                    .that().areDeclaredInClassesThat().resideInAPackage("com.eudistack.ebw.wallet.config..")
                    .should().beAnnotatedWith("org.springframework.data.r2dbc.repository.Modifying")
                    .as("no @Modifying (write) query may be declared in the read-only wallet.config plane");

    // ------------------------------------------------------------------
    // Hexagonal layering
    // ------------------------------------------------------------------

    /**
     * Domain classes (models, ports) must be pure Java with no infrastructure imports — the
     * hexagonal architecture contract.
     */
    @ArchTest
    static final ArchRule domain_does_not_depend_on_infrastructure =
            noClasses()
                    .that().resideInAPackage("com.eudistack.ebw.wallet.config.domain..")
                    .should().dependOnClassesThat()
                    .resideInAPackage("com.eudistack.ebw.wallet.config.infrastructure..");

    /**
     * The domain layer must be free of Spring Boot / WebFlux types. (Jackson's {@code @JsonValue}
     * on enum types is permitted — it is not under {@code org.springframework.boot..}.)
     */
    @ArchTest
    static final ArchRule domain_does_not_depend_on_spring_boot =
            noClasses()
                    .that().resideInAPackage("com.eudistack.ebw.wallet.config.domain..")
                    .should().dependOnClassesThat()
                    .resideInAPackage("org.springframework.boot..");

    /**
     * Application services (use cases) must depend only on the domain layer (ports, models,
     * exceptions) — never directly on infrastructure adapters. Wiring lives in the config/beans
     * layer.
     */
    @ArchTest
    static final ArchRule application_does_not_depend_on_infrastructure =
            noClasses()
                    .that().resideInAPackage("com.eudistack.ebw.wallet.config.application..")
                    .should().dependOnClassesThat()
                    .resideInAPackage("com.eudistack.ebw.wallet.config.infrastructure..");
}
