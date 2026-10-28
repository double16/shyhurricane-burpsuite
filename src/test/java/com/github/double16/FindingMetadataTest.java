package com.github.double16;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

class FindingMetadataTest {
  @Test
  void labels() {
    String[] nativeLabels = {
      "High", "Medium", "Low", "Information", "Informational", "bogus", "FALSE_POSITIVE"
    };
    String[] expected = {
      "high", "medium", "low", "informational", "informational", "unknown", "unknown"
    };
    for (int i = 0; i < nativeLabels.length; i++)
      assertEquals(expected[i], ExtensionShyHurricaneForwarder.normalize(nativeLabels[i], false));
    assertEquals("high", ExtensionShyHurricaneForwarder.normalize("Certain", true));
    assertEquals("medium", ExtensionShyHurricaneForwarder.normalize("Firm", true));
    assertEquals("low", ExtensionShyHurricaneForwarder.normalize("Tentative", true));
    assertEquals("unknown", ExtensionShyHurricaneForwarder.normalize("bogus", true));
  }

  @Test
  void failures() {
    assertTrue(ExtensionShyHurricaneForwarder.retryable(new java.net.ConnectException()));
    for (int code : new int[] {408, 429, 500, 503})
      assertTrue(
          ExtensionShyHurricaneForwarder.retryable(
              new ExtensionShyHurricaneForwarder.PostFailureException(code)));
    assertFalse(
        ExtensionShyHurricaneForwarder.retryable(
            new ExtensionShyHurricaneForwarder.PostFailureException(400)));
    assertFalse(ExtensionShyHurricaneForwarder.retryable(new javax.net.ssl.SSLException("test")));
  }
}
