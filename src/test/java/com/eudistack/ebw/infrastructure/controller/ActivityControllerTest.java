package com.eudistack.ebw.infrastructure.controller;

import com.eudistack.ebw.application.workflow.ListActivityWorkflow;
import com.eudistack.ebw.application.workflow.RecordActivityWorkflow;
import com.eudistack.ebw.domain.model.ActivityType;
import com.eudistack.ebw.domain.model.WalletActivity;
import com.eudistack.ebw.infrastructure.controller.dto.RecordActivityRequest;
import com.eudistack.ebw.infrastructure.security.JwtAuthenticationToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link ActivityController} — activity type parsing and holder-scoped listing (EUD-141).
 * The HTTP contract is covered by {@link ActivityControllerIT}.
 */
@ExtendWith(MockitoExtension.class)
class ActivityControllerTest {

    private static final UUID USER_ID = UUID.randomUUID();

    @Mock private RecordActivityWorkflow recordActivityWorkflow;
    @Mock private ListActivityWorkflow listActivityWorkflow;

    private ActivityController controller;
    private JwtAuthenticationToken auth;

    @BeforeEach
    void setUp() {
        controller = new ActivityController(recordActivityWorkflow, listActivityWorkflow);
        auth = new JwtAuthenticationToken(USER_ID, "holder@example.com", List.of());
    }

    @Test
    void record_knownType_recordsActivityAndReturnsIt() {
        // Arrange
        var activityId = UUID.randomUUID();
        var request = new RecordActivityRequest(activityId, "PRESENTED", "LEAR", "https://verifier",
                "details", List.of("given_name"));
        var activity = new WalletActivity(activityId, USER_ID, ActivityType.PRESENTED, "LEAR", "https://verifier",
                "details", List.of("given_name"), Instant.now());
        when(recordActivityWorkflow.recordActivity(USER_ID, activityId, ActivityType.PRESENTED, "LEAR",
                "https://verifier", "details", List.of("given_name"))).thenReturn(Mono.just(activity));

        // Act
        var result = controller.record(request, auth);

        // Assert
        StepVerifier.create(result)
                .assertNext(response -> {
                    assertThat(response.id()).isEqualTo(activityId);
                    assertThat(response.type()).isEqualTo("PRESENTED");
                    assertThat(response.sharedAttributes()).containsExactly("given_name");
                })
                .verifyComplete();
    }

    @Test
    void record_unknownType_failsWithIllegalArgumentWithoutRecording() {
        // Arrange
        var request = new RecordActivityRequest(UUID.randomUUID(), "SIGNED", "LEAR", "cp", null, null);

        // Act
        var result = controller.record(request, auth);

        // Assert
        StepVerifier.create(result)
                .expectErrorMatches(e -> e instanceof IllegalArgumentException
                        && e.getMessage().equals("Invalid activity type: SIGNED"))
                .verify();
        verifyNoInteractions(recordActivityWorkflow);
    }

    @Test
    void list_holderActivity_returnsItMappedToResponses() {
        // Arrange
        var activity = WalletActivity.create(USER_ID, ActivityType.ISSUED, "LEAR", "https://issuer", null, null);
        when(listActivityWorkflow.listActivity(USER_ID)).thenReturn(Flux.just(activity));

        // Act
        var result = controller.list(auth);

        // Assert
        StepVerifier.create(result)
                .assertNext(list -> {
                    assertThat(list).hasSize(1);
                    assertThat(list.get(0).type()).isEqualTo("ISSUED");
                    assertThat(list.get(0).counterparty()).isEqualTo("https://issuer");
                })
                .verifyComplete();
    }
}
