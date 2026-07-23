package com.eudistack.ebw.keymanager;

import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchRule;
import org.springframework.beans.factory.annotation.Autowired;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.fields;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

/**
 * Enforces the hexagonal-discipline layering rules for the Key Manager bounded context:
 * domain must not depend on application/infrastructure, application must not depend on
 * infrastructure, and constructor injection is used exclusively (no {@code @Autowired} fields).
 *
 * <p>Rules: {@code ../eudistack-platform-dev/.claude/rules/hexagonal-discipline.md}.</p>
 */
@AnalyzeClasses(packages = "com.eudistack.ebw.keymanager", importOptions = ImportOption.DoNotIncludeTests.class)
class KeyManagerArchitectureTest {

    @ArchTest
    static final ArchRule domainMustNotDependOnApplicationOrInfrastructure = noClasses()
            .that().resideInAPackage("..keymanager.domain..")
            .should().dependOnClassesThat().resideInAnyPackage(
                    "..keymanager.application..", "..keymanager.infrastructure..");

    @ArchTest
    static final ArchRule applicationMustNotDependOnInfrastructure = noClasses()
            .that().resideInAPackage("..keymanager.application..")
            .should().dependOnClassesThat().resideInAPackage("..keymanager.infrastructure..");

    @ArchTest
    static final ArchRule noFieldInjection = fields()
            .that().areDeclaredInClassesThat().resideInAPackage("..keymanager..")
            .should().notBeAnnotatedWith(Autowired.class);
}
