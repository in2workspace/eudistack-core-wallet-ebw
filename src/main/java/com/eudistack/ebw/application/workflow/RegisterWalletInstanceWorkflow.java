package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.WalletInstance;
import com.eudistack.ebw.domain.model.WalletInstance.DeviceType;
import com.eudistack.ebw.domain.model.exception.InvalidSessionException;
import com.eudistack.ebw.domain.model.exception.InvalidWalletInstanceException;
import com.eudistack.ebw.domain.repository.RefreshTokenRepository;
import com.eudistack.ebw.domain.repository.WalletInstanceRepository;
import com.eudistack.ebw.domain.repository.WalletUserRepository;
import com.eudistack.ebw.domain.service.AuditService;
import com.eudistack.ebw.domain.spi.IpRateLimiter;
import com.eudistack.ebw.domain.spi.TransactionRunner;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;

/**
 * Registers the Wallet App of the session as a new Wallet Instance of the account and binds the session to it
 * (EUD-15 FR-01 to FR-04, FR-08, design §2.1). Only with an open session of the account (FR-02): the route is
 * authenticated. The instance (active, with its name, type, the passkey of the session and the date) and the
 * binding are one transaction; if the session was bound to another instance it is rebound, and the previous one
 * is not revoked. After the commit the single email of the registration goes ({@link WalletInstanceNotices}).
 *
 * <p>At most {@value #REGISTRATIONS_PER_HOUR} registrations per account and hour (design §2.1): the counter is the
 * shared one of the rate limits, keyed by tenant and account, since the account is only known once the request is
 * authenticated, so its window is {@code ebw.rate-limit.window} (1 hour by default, the hour of the design).
 */
@Service
public class RegisterWalletInstanceWorkflow {

    static final int REGISTRATIONS_PER_HOUR = 20;
    /**
     * The first device of an account created this long ago at most is the first device of a new account and
     * confirms the complete sign-up (FR-08). An account that existed before the Wallet Instances gets the
     * new-device email for its first one instead.
     */
    static final Duration NEW_ACCOUNT_WINDOW = Duration.ofHours(24);
    private static final String RATE_KEY_PREFIX = "wallet-instance-registration:";

    private final WalletInstanceRepository instanceRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final WalletUserRepository userRepository;
    private final AuditService auditService;
    private final TransactionRunner transactionRunner;
    private final IpRateLimiter rateLimiter;
    private final EmailLocales emailLocales;
    private final WalletInstanceNotices notices;

    /** A registration request: the name and type the Wallet App proposes or the user typed. */
    public record RegisterCommand(String displayName, String deviceType) {}

    private record Registered(WalletInstance instance, boolean firstInstance, boolean passkeyAdded) {}

    @SuppressWarnings("java:S107")
    public RegisterWalletInstanceWorkflow(WalletInstanceRepository instanceRepository,
                                          RefreshTokenRepository refreshTokenRepository,
                                          WalletUserRepository userRepository, AuditService auditService,
                                          TransactionRunner transactionRunner, IpRateLimiter rateLimiter,
                                          EmailLocales emailLocales, WalletInstanceNotices notices) {
        this.instanceRepository = instanceRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.userRepository = userRepository;
        this.auditService = auditService;
        this.transactionRunner = transactionRunner;
        this.rateLimiter = rateLimiter;
        this.emailLocales = emailLocales;
        this.notices = notices;
    }

    /**
     * @throws InvalidWalletInstanceException (signal) empty or too long name, unknown device type
     * @throws com.eudistack.ebw.domain.model.exception.RateLimitExceededException (signal) too many registrations
     */
    public Mono<WalletInstance> register(WalletSession session, RegisterCommand command) {
        var displayName = WalletInstance.normalizeDisplayName(command.displayName());
        if (displayName == null) {
            return Mono.error(new InvalidWalletInstanceException("displayName"));
        }
        var deviceType = parseDeviceType(command.deviceType());
        if (deviceType == null) {
            return Mono.error(new InvalidWalletInstanceException("deviceType"));
        }
        var instance = WalletInstance.register(session.userId(), displayName, deviceType, session.passkeyId());
        return SessionOpener.currentTenant()
                .flatMap(tenant -> rateLimiter.check(RATE_KEY_PREFIX + tenant + ":" + session.userId(),
                        REGISTRATIONS_PER_HOUR))
                .then(transactionRunner.inTransaction(store(session, instance)))
                .flatMap(registered -> emailLocales.rememberRequestLanguage(session.userId())
                        .then(userRepository.findById(session.userId()))
                        .switchIfEmpty(Mono.error(new InvalidSessionException()))
                        .flatMap(user -> notices.deviceRegistered(new WalletInstanceNotices.Registration(user,
                                registered.instance(),
                                registered.firstInstance() && isNew(user.getCreatedAt()),
                                registered.passkeyAdded())))
                        .thenReturn(registered.instance()));
    }

    /** Instance, binding, the pending new-passkey mark taken (it goes inside this email) and the trace. */
    private Mono<Registered> store(WalletSession session, WalletInstance instance) {
        // The account row is locked first, so two registrations at once never both count as the first device.
        return userRepository.lockById(session.userId())
                .then(instanceRepository.countByUserId(session.userId()))
                .flatMap(previous -> instanceRepository.insert(instance)
                        .then(refreshTokenRepository.bindSession(session.sessionId(), instance.id()))
                        .then(refreshTokenRepository.clearPasskeyNoticePending(session.sessionId()))
                        .flatMap(passkeyAdded -> auditService.record(WalletInstanceAuditEvents.ENTITY_WALLET_INSTANCE,
                                        instance.id(), WalletInstanceAuditEvents.WALLET_INSTANCE_REGISTERED,
                                        session.userId(), Map.of("device_type", instance.deviceType().name(),
                                                "session_id", session.sessionId().toString()))
                                .thenReturn(new Registered(instance, previous == 0, passkeyAdded))));
    }

    private static boolean isNew(Instant accountCreatedAt) {
        return accountCreatedAt != null && accountCreatedAt.isAfter(Instant.now().minus(NEW_ACCOUNT_WINDOW));
    }

    static DeviceType parseDeviceType(String raw) {
        if (raw == null) {
            return null;
        }
        return switch (raw) {
            case "mobile" -> DeviceType.MOBILE;
            case "tablet" -> DeviceType.TABLET;
            case "desktop" -> DeviceType.DESKTOP;
            default -> null;
        };
    }
}
