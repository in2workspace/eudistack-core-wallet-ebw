package com.eudistack.ebw.infrastructure.adapter.r2dbc;

import com.eudistack.ebw.domain.model.WalletActivity;
import com.eudistack.ebw.domain.repository.WalletActivityRepository;
import com.eudistack.ebw.infrastructure.adapter.r2dbc.mapper.ActivityMapper;
import com.eudistack.ebw.infrastructure.adapter.r2dbc.spring.SpringWalletActivityRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.UUID;

@Repository
public class WalletActivityR2dbcRepository implements WalletActivityRepository {

    private final SpringWalletActivityRepository springRepository;

    public WalletActivityR2dbcRepository(SpringWalletActivityRepository springRepository) {
        this.springRepository = springRepository;
    }

    @Override
    public Mono<WalletActivity> insertIfAbsent(WalletActivity activity) {
        var entity = ActivityMapper.toEntity(activity);
        return springRepository.insertIfAbsent(entity.getId(), entity.getUserId(), entity.getType(),
                        entity.getCredentialName(), entity.getCounterparty(), entity.getDetails(),
                        entity.getSharedAttributes(), entity.getCreatedAt())
                .map(ActivityMapper::toDomain);
    }

    @Override
    public Flux<WalletActivity> findRecentByUserId(UUID userId, int limit) {
        return springRepository.findRecentByUserId(userId, limit)
                .map(ActivityMapper::toDomain);
    }
}
