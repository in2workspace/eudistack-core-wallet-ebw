package com.eudistack.ebw.domain.spi;

import java.util.Map;

public interface TokenSigner {

    String sign(Map<String, Object> claims);

    Map<String, Object> verify(String token);
}
