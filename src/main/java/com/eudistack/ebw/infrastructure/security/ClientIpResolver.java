package com.eudistack.ebw.infrastructure.security;

import com.eudistack.ebw.infrastructure.adapter.properties.RateLimitProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.regex.Pattern;

/**
 * Resolves the client the rate limits are keyed on. Each trusted proxy appends the address it received the
 * request from, so only the entries counted from the end of {@code X-Forwarded-For} come from our own
 * infrastructure; whatever the client wrote sits at the start and is never read. A request with fewer entries
 * than trusted proxies skipped part of the chain, so no entry can be trusted and it is counted by its
 * connection address.
 *
 * <p>The key is canonical: IPv4 without leading zeros, and IPv6 reduced to its /64 prefix, because one client
 * holds a whole /64 and could otherwise take a new address for every request.
 */
@Component
@RequiredArgsConstructor
public class ClientIpResolver {

    private static final String FORWARDED_FOR = "X-Forwarded-For";
    private static final String UNKNOWN = "unknown";
    private static final Pattern IPV4 = Pattern.compile("^(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})$");
    private static final Pattern IPV6_CHARACTERS = Pattern.compile("^[0-9A-Fa-f:.]{2,45}$");

    private final RateLimitProperties properties;

    public String resolve(ServerHttpRequest request) {
        var entries = Arrays.stream(String.join(",", request.getHeaders().getOrEmpty(FORWARDED_FOR)).split(","))
                .map(String::trim)
                .filter(entry -> !entry.isEmpty())
                .toList();
        if (entries.size() >= properties.trustedProxies()) {
            var key = keyOfLiteral(entries.get(entries.size() - properties.trustedProxies()));
            if (key != null) {
                return key;
            }
        }
        var remoteAddress = request.getRemoteAddress();
        return remoteAddress != null && remoteAddress.getAddress() != null
                ? keyOf(remoteAddress.getAddress())
                : UNKNOWN;
    }

    /** Null when the text is not an IP address. */
    private static String keyOfLiteral(String literal) {
        var ipv4 = IPV4.matcher(literal);
        if (ipv4.matches()) {
            var octets = new int[4];
            for (int i = 0; i < 4; i++) {
                octets[i] = Integer.parseInt(ipv4.group(i + 1));
                if (octets[i] > 255) {
                    return null;
                }
            }
            return octets[0] + "." + octets[1] + "." + octets[2] + "." + octets[3];
        }
        if (literal.indexOf(':') >= 0 && IPV6_CHARACTERS.matcher(literal).matches()) {
            try {
                // A text with ':' is parsed as an IPv6 literal and never looked up in the DNS.
                return keyOf(InetAddress.getByName(literal));
            } catch (UnknownHostException _) {
                return null;
            }
        }
        return null;
    }

    private static String keyOf(InetAddress address) {
        if (address instanceof Inet6Address) {
            var bytes = address.getAddress();
            return String.format("%04x:%04x:%04x:%04x::/64",
                    group(bytes, 0), group(bytes, 2), group(bytes, 4), group(bytes, 6));
        }
        return address.getHostAddress();
    }

    private static int group(byte[] bytes, int offset) {
        return ((bytes[offset] & 0xff) << 8) | (bytes[offset + 1] & 0xff);
    }
}
