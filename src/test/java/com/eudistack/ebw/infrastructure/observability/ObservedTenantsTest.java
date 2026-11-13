package com.eudistack.ebw.infrastructure.observability;

import com.eudistack.ebw.infrastructure.configuration.ActiveTenantDirectory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.ObjectProvider;
import reactor.core.publisher.Flux;
import reactor.test.StepVerifier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/** Unit tests for {@link ObservedTenants}. */
@ExtendWith(MockitoExtension.class)
class ObservedTenantsTest {

    @Mock private ActiveTenantDirectory tenantDirectory;
    @Mock private ObjectProvider<ActiveTenantDirectory> tenantDirectoryProvider;

    private ObservedTenants observedTenants;

    @BeforeEach
    void setUp() {
        observedTenants = new ObservedTenants(tenantDirectoryProvider);
    }

    @Test
    void tagValue_beforeTheFirstRefresh_isUnknown() {
        assertThat(observedTenants.tagValue("sandbox")).isEqualTo(ObservedTenants.UNKNOWN_TENANT);
    }

    @Test
    void tagValue_activeTenant_isTheTenant() {
        // Arrange
        when(tenantDirectoryProvider.getObject()).thenReturn(tenantDirectory);
        when(tenantDirectory.activeTenants()).thenReturn(Flux.just("sandbox", "kpmg"));

        // Act
        StepVerifier.create(observedTenants.refresh()).expectNext(2).verifyComplete();

        // Assert
        assertThat(observedTenants.tagValue("sandbox")).isEqualTo("sandbox");
        assertThat(observedTenants.tagValue("kpmg")).isEqualTo("kpmg");
    }

    @Test
    void tagValue_tenantNotActive_isUnknown() {
        // Arrange: a subdomain with a valid shape that is not a tenant
        when(tenantDirectoryProvider.getObject()).thenReturn(tenantDirectory);
        when(tenantDirectory.activeTenants()).thenReturn(Flux.just("sandbox"));
        StepVerifier.create(observedTenants.refresh()).expectNext(1).verifyComplete();

        // Act + Assert
        assertThat(observedTenants.tagValue("invented")).isEqualTo(ObservedTenants.UNKNOWN_TENANT);
    }

    @Test
    void tagValue_noTenant_isUnknown() {
        assertThat(observedTenants.tagValue(null)).isEqualTo(ObservedTenants.UNKNOWN_TENANT);
    }

    @Test
    void refresh_tenantNoLongerActive_becomesUnknown() {
        // Arrange
        when(tenantDirectoryProvider.getObject()).thenReturn(tenantDirectory);
        when(tenantDirectory.activeTenants()).thenReturn(Flux.just("sandbox", "kpmg"), Flux.just("sandbox"));
        StepVerifier.create(observedTenants.refresh()).expectNext(2).verifyComplete();

        // Act
        StepVerifier.create(observedTenants.refresh()).expectNext(1).verifyComplete();

        // Assert
        assertThat(observedTenants.tagValue("kpmg")).isEqualTo(ObservedTenants.UNKNOWN_TENANT);
        assertThat(observedTenants.tagValue("sandbox")).isEqualTo("sandbox");
    }

    @Test
    void refresh_tenantRegistryUnavailable_keepsThePreviousList() {
        // Arrange
        when(tenantDirectoryProvider.getObject()).thenReturn(tenantDirectory);
        when(tenantDirectory.activeTenants())
                .thenReturn(Flux.just("sandbox"), Flux.error(new IllegalStateException("db down")));
        StepVerifier.create(observedTenants.refresh()).expectNext(1).verifyComplete();

        // Act
        StepVerifier.create(observedTenants.refresh()).expectNext(1).verifyComplete();

        // Assert
        assertThat(observedTenants.tagValue("sandbox")).isEqualTo("sandbox");
    }
}
