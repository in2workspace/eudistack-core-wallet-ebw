package com.eudistack.ebw.wallet.config.architecture;

import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchRule;

import static com.tngtech.archunit.core.domain.JavaClass.Predicates.simpleName;
import static com.tngtech.archunit.core.domain.JavaClass.Predicates.simpleNameContaining;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noMethods;

/**
 * ArchUnit architecture tests for the {@code wallet.config} bounded context — covers T-5 and T-7
 * (AD-1, AD-3, AD-S1, E-11) from tech-design §2.3 and EUDISTACK-414 §3.5.
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
 *
 * <p>EUDISTACK-414 extends this suite with three rules enforcing dual-plane separation between
 * the discovery plane ({@code WalletTenantConfig*}) and the operational plane
 * ({@code OperationalConfig*}, KMS, probe):
 * <ol>
 *   <li><strong>Operational adapters must not use the public-schema pool (AD-1, AD-S1).</strong>
 *       Operational R2DBC adapters use the tenant-aware default {@code ConnectionFactory} — never
 *       {@code PublicSchemaConnectionFactory}.</li>
 *   <li><strong>Discovery plane must not touch operational ports (AD-3).</strong>
 *       {@code WalletTenantConfig*} classes must not depend on any operational port or adapter.</li>
 *   <li><strong>Only R2DBC adapter packages may depend on {@code DatabaseClient} (hexagonal
 *       discipline).</strong> Domain, application, controller, KMS and probe layers route through
 *       ports — they never hold a direct {@code DatabaseClient} reference.</li>
 * </ol>
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

    // ------------------------------------------------------------------
    // EUDISTACK-414 — Dual-plane separation (T-7, AD-1, AD-3, AD-S1)
    // ------------------------------------------------------------------

    /**
     * Operational R2DBC adapters must use the tenant-aware default {@code ConnectionFactory} —
     * never {@code PublicSchemaConnectionFactory}, which is pinned to {@code search_path = public}
     * and is reserved exclusively for the discovery plane.
     *
     * <p>A dependency here would silently bypass per-tenant schema isolation, writing operational
     * config into the wrong schema — a critical data-isolation violation (AD-1, AD-S1,
     * EUDISTACK-414 §3.5).
     */
    @ArchTest
    static final ArchRule operational_adapters_must_not_depend_on_public_schema_connection_factory =
            noClasses()
                    .that()
                    .resideInAPackage(
                            "com.eudistack.ebw.wallet.config.infrastructure.adapter.r2dbc")
                    .and().haveSimpleNameContaining("Operational")
                    .should().dependOnClassesThat()
                    .haveSimpleName("PublicSchemaConnectionFactory")
                    .because("operational adapters must use the tenant-aware default ConnectionFactory;"
                            + " only the discovery plane uses PublicSchemaConnectionFactory"
                            + " (AD-1, AD-S1, EUDISTACK-414 §3.5)");

    /**
     * The discovery plane ({@code WalletTenantConfig*}) must never depend on operational ports
     * ({@code *Operational*}), {@code KeyManagerConnectivityPort}, or
     * {@code EnvelopeEncryptionPort}.
     *
     * <p>This enforces the dual-plane separation mandated by AD-3: the discovery read path reads
     * only from the {@code public} schema and has no awareness of operational KMS or encryption
     * concerns. A cross-plane dependency here would create an unintended coupling that the reviewer
     * cannot detect at runtime — only statically (EUDISTACK-414 §3.5).
     */
    @ArchTest
    static final ArchRule discovery_plane_must_not_depend_on_operational_ports =
            noClasses()
                    .that().haveSimpleNameContaining("WalletTenantConfig")
                    .should()
                    .dependOnClassesThat(
                            simpleNameContaining("Operational")
                                    .or(simpleName("KeyManagerConnectivityPort"))
                                    .or(simpleName("EnvelopeEncryptionPort")))
                    .because("dual-plane separation: the discovery plane (WalletTenantConfig*) must"
                            + " never depend on operational ports or adapters (AD-3, EUDISTACK-414 §3.5)");

    /**
     * Only packages that form the R2DBC adapter layer ({@code adapter.r2dbc} and
     * {@code infrastructure.config}) may hold a direct reference to
     * {@link org.springframework.r2dbc.core.DatabaseClient}.
     *
     * <p>Domain, application, controller, KMS, and probe layers must interact with the database
     * exclusively through hexagonal ports — never by calling {@code DatabaseClient} directly.
     * Mixing persistence mechanics into domain or application code collapses the port boundary and
     * makes the unit-testable core depend on R2DBC at compile time.
     */
    @ArchTest
    static final ArchRule only_r2dbc_adapter_packages_may_use_database_client =
            noClasses()
                    .that()
                    .resideInAnyPackage(
                            "com.eudistack.ebw.wallet.config.domain..",
                            "com.eudistack.ebw.wallet.config.application..",
                            "com.eudistack.ebw.wallet.config.infrastructure.controller..",
                            "com.eudistack.ebw.wallet.config.infrastructure.adapter.kms..",
                            "com.eudistack.ebw.wallet.config.infrastructure.adapter.probe..")
                    .should()
                    .dependOnClassesThat()
                    .haveFullyQualifiedName("org.springframework.r2dbc.core.DatabaseClient")
                    .because("DatabaseClient is an infrastructure detail; only R2DBC adapters and"
                            + " their wiring beans may use it directly — everything else routes through ports");
}
