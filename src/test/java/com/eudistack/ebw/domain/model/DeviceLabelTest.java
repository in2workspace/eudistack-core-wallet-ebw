package com.eudistack.ebw.domain.model;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

/** Unit tests for {@link DeviceLabel} (EUD-315 P19, EC-16). */
class DeviceLabelTest {

    @ParameterizedTest
    @CsvSource(delimiter = '|', value = {
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1|iPhone · Safari",
            "Mozilla/5.0 (iPad; CPU OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/126.0.6478.153 Mobile/15E148 Safari/604.1|iPad · Chrome",
            "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36|Android · Chrome",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0|Windows · Edge",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36|Windows · Chrome",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15|Mac · Safari",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:127.0) Gecko/20100101 Firefox/127.0|Mac · Firefox",
            "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/25.0 Chrome/121.0.0.0 Mobile Safari/537.36|Android · Samsung Internet",
            "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0|Linux · Firefox",
    })
    void of_realUserAgent_givesTheDeviceAndTheBrowserOfTheClosedLists(String userAgent, String expected) {
        // Act + Assert
        assertThat(DeviceLabel.of(userAgent).value()).isEqualTo(expected);
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   ", "curl/8.4.0", "\u0000\u0001 garbage ~~~"})
    void of_missingOrNotRecognized_givesTheGenericLabel(String userAgent) {
        // Act + Assert
        assertThat(DeviceLabel.of(userAgent).value()).isEqualTo("Other device · Other browser");
    }

    @Test
    void of_userAgentWithInjectedText_neverEchoesIt() {
        // Arrange: EC-16, text an attacker puts in the header to appear in an email with the tenant's brand
        var userAgent = "Registrado por RRHH <b>haga clic</b> https://evil.example/ Windows NT 10.0 Firefox/127.0";

        // Act
        var label = DeviceLabel.of(userAgent).value();

        // Assert: only closed-list words come out
        assertThat(label).isEqualTo("Windows · Firefox")
                .doesNotContain("RRHH").doesNotContain("evil").doesNotContain("<");
    }
}
