package com.github.double16;

import static com.github.double16.ForwarderFixtures.*;
import static org.junit.jupiter.api.Assertions.*;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.util.*;
import org.junit.jupiter.api.Test;

class FindingDeliveryTest {
  @Test
  void retryUsesIdenticalPayloadAndContinuesAfterPermanentFailure() throws Exception {
    final List<String> bodies = new ArrayList<>();
    final var server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext(
        "/findings",
        exchange -> {
          bodies.add(
              new String(
                  exchange.getRequestBody().readAllBytes(),
                  java.nio.charset.StandardCharsets.UTF_8));
          exchange.sendResponseHeaders(
              bodies.size() == 1 ? 503 : bodies.size() == 2 ? 400 : 201, -1);
          exchange.close();
        });
    server.start();
    final var forwarder =
        new ExtensionShyHurricaneForwarder() {
          @Override
          void retryDelay(long millis) {}
        };
    try {
      forwarder.setMcpServerUrl("http://127.0.0.1:" + server.getAddress().getPort());
      final var first =
          stub(
              HttpRequest.class,
              Map.of("url", "https://example.com/search?q=%2F", "method", "get"));
      final var second =
          stub(
              HttpRequest.class,
              Map.of("url", "https://example.com/search?q=other", "method", "POST"));
      final var issue =
          stub(
              AuditIssue.class,
              Map.of(
                  "baseUrl",
                  "https://example.com",
                  "requestResponses",
                  List.of(message(first, null), message(second, null))));
      assertThrows(Exception.class, () -> forwarder.sendIssue(issue));
      assertEquals(3, bodies.size());
      assertEquals(bodies.get(0), bodies.get(1));
      final var json = new ObjectMapper().readTree(bodies.get(0));
      assertEquals("https://example.com/search?q=%2F", json.path("target").asText());
      assertEquals("GET", json.path("metadata").path("affected_method").asText());
      assertEquals(
          Set.of("source", "verification_status", "affected_method"),
          new ObjectMapper().convertValue(json.path("metadata"), Map.class).keySet());
      forwarder.extensionUnloaded();
      assertThrows(InterruptedException.class, () -> forwarder.sendIssue(issue));
      assertEquals(3, bodies.size());
    } finally {
      forwarder.extensionUnloaded();
      server.stop(0);
    }
  }

  @Test
  void sparseMetadataOmitsUnsupportedFields() {
    assertEquals(
        Map.of("source", "burp", "verification_status", "unverified"),
        ExtensionShyHurricaneForwarder.metadata(stub(AuditIssue.class, Map.of()), null));
  }
}
