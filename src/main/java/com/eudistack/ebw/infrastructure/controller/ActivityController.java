package com.eudistack.ebw.infrastructure.controller;

import com.eudistack.ebw.application.workflow.ListActivityWorkflow;
import com.eudistack.ebw.application.workflow.RecordActivityWorkflow;
import com.eudistack.ebw.domain.model.ActivityType;
import com.eudistack.ebw.infrastructure.controller.dto.ActivityResponse;
import com.eudistack.ebw.infrastructure.controller.dto.RecordActivityRequest;
import com.eudistack.ebw.infrastructure.security.JwtAuthenticationToken;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.util.List;

@RestController
@RequestMapping("/api/v1/activity")
@Validated
public class ActivityController {

    private final RecordActivityWorkflow recordActivityWorkflow;
    private final ListActivityWorkflow listActivityWorkflow;

    public ActivityController(RecordActivityWorkflow recordActivityWorkflow,
                               ListActivityWorkflow listActivityWorkflow) {
        this.recordActivityWorkflow = recordActivityWorkflow;
        this.listActivityWorkflow = listActivityWorkflow;
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public Mono<ActivityResponse> record(@Valid @RequestBody RecordActivityRequest request,
                                          JwtAuthenticationToken auth) {
        ActivityType type;
        try {
            type = ActivityType.valueOf(request.type());
        } catch (IllegalArgumentException e) {
            return Mono.error(new IllegalArgumentException("Invalid activity type: " + request.type()));
        }

        return recordActivityWorkflow.recordActivity(auth.getUserId(), request.id(), type,
                        request.credentialName(), request.counterparty(), request.details(),
                        request.sharedAttributes())
                .map(ActivityResponse::from);
    }

    @GetMapping
    public Mono<List<ActivityResponse>> list(JwtAuthenticationToken auth) {
        return listActivityWorkflow.listActivity(auth.getUserId())
                .map(ActivityResponse::from)
                .collectList();
    }
}
