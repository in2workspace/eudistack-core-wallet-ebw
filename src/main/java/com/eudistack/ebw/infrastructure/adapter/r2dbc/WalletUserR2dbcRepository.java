package com.eudistack.ebw.infrastructure.adapter.r2dbc;

import com.eudistack.ebw.domain.model.WalletUser;
import com.eudistack.ebw.domain.repository.WalletUserRepository;
import com.eudistack.ebw.infrastructure.adapter.r2dbc.mapper.UserMapper;
import com.eudistack.ebw.infrastructure.adapter.r2dbc.spring.SpringWalletUserRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;

import java.util.UUID;

@Repository
public class WalletUserR2dbcRepository implements WalletUserRepository {

    private final SpringWalletUserRepository springRepository;

    public WalletUserR2dbcRepository(SpringWalletUserRepository springRepository) {
        this.springRepository = springRepository;
    }

    @Override
    public Mono<WalletUser> findById(UUID id) {
        return springRepository.findById(id).map(UserMapper::toDomain);
    }

    @Override
    public Mono<WalletUser> findByEmail(String email) {
        return springRepository.findByEmail(email).map(UserMapper::toDomain);
    }

    @Override
    public Mono<WalletUser> save(WalletUser user) {
        return springRepository.existsById(user.getId())
                .flatMap(exists -> {
                    var entity = UserMapper.toEntity(user);
                    if (!exists) entity.markNew();
                    return springRepository.save(entity);
                })
                .map(UserMapper::toDomain);
    }
}
