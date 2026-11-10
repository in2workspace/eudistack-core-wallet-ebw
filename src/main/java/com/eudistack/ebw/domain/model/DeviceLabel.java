package com.eudistack.ebw.domain.model;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Device shown in the email of a passkey registered with an onboarding ticket, such as
 * {@code iPhone · Safari} (EUD-315 decision P19, EC-16). The service derives it from the
 * {@code User-Agent} with closed lists: nothing of the header reaches the email, so a person who
 * intercepts the ticket cannot write text into a message that carries the tenant's brand.
 *
 * @param value device, a space, a middle dot, a space and browser
 */
public record DeviceLabel(String value) {

    public static final String OTHER_DEVICE = "Other device";
    public static final String OTHER_BROWSER = "Other browser";

    /**
     * Ordered: Android UAs also say {@code Linux}, iPhone and iPad UAs say {@code like Mac OS X}.
     * An iPad on iPadOS may present itself as a Mac, which this list does not try to tell apart.
     */
    private static final Map<String, String> DEVICES = new LinkedHashMap<>();

    /**
     * Ordered: Edge and Samsung Internet UAs also say {@code Chrome}, and Chrome's says {@code Safari}.
     * Firefox on iOS says {@code FxiOS} and Chrome on iOS {@code CriOS}.
     */
    private static final Map<String, String> BROWSERS = new LinkedHashMap<>();

    static {
        DEVICES.put("iPhone", "iPhone");
        DEVICES.put("iPad", "iPad");
        DEVICES.put("Android", "Android");
        DEVICES.put("Windows", "Windows");
        DEVICES.put("Macintosh", "Mac");
        DEVICES.put("Mac OS X", "Mac");
        DEVICES.put("Linux", "Linux");

        BROWSERS.put("Edg/", "Edge");
        BROWSERS.put("EdgA/", "Edge");
        BROWSERS.put("EdgiOS/", "Edge");
        BROWSERS.put("Edge/", "Edge");
        BROWSERS.put("SamsungBrowser/", "Samsung Internet");
        BROWSERS.put("Firefox/", "Firefox");
        BROWSERS.put("FxiOS/", "Firefox");
        BROWSERS.put("Chrome/", "Chrome");
        BROWSERS.put("CriOS/", "Chrome");
        BROWSERS.put("Safari/", "Safari");
    }

    /** Label of a request's {@code User-Agent}; the generic one if it is missing or not recognized. */
    public static DeviceLabel of(String userAgent) {
        return new DeviceLabel(firstMatch(DEVICES, userAgent, OTHER_DEVICE) + " · "
                + firstMatch(BROWSERS, userAgent, OTHER_BROWSER));
    }

    private static String firstMatch(Map<String, String> known, String userAgent, String fallback) {
        if (userAgent == null || userAgent.isBlank()) {
            return fallback;
        }
        return known.entrySet().stream()
                .filter(entry -> userAgent.contains(entry.getKey()))
                .map(Map.Entry::getValue)
                .findFirst()
                .orElse(fallback);
    }
}
