package com.github.double16;

import static com.github.double16.ForwarderFixtures.*;
import static org.junit.jupiter.api.Assertions.*;

import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.ui.contextmenu.AuditIssueContextMenuEvent;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import javax.swing.JMenuItem;
import javax.swing.SwingUtilities;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class ManualForwardingTest {
  private HttpServer server;
  private ExtensionShyHurricaneForwarder forwarder;
  private final LinkedBlockingQueue<Recorded> posts = new LinkedBlockingQueue<>();
  private volatile int serverStatus = 200;

  private record Recorded(String path, String contentType, JsonNode body) {}

  @BeforeEach
  void start() throws Exception {
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext(
        "/",
        exchange -> {
          try (exchange) {
            posts.add(
                new Recorded(
                    exchange.getRequestURI().getPath(),
                    exchange.getRequestHeaders().getFirst("Content-Type"),
                    new ObjectMapper()
                        .readTree(
                            new String(
                                exchange.getRequestBody().readAllBytes(),
                                StandardCharsets.UTF_8))));
            exchange.getResponseHeaders().set("Location", "/redirected");
            exchange.sendResponseHeaders(serverStatus, -1);
          }
        });
    server.start();
    forwarder = new ExtensionShyHurricaneForwarder();
    forwarder.setMcpServerUrl("http://127.0.0.1:" + server.getAddress().getPort());
    forwarder.setOnlyInScope(true);
    forwarder.setAllTools(false);
    forwarder.setSelectedToolNames(Set.of());
    forwarder.setSelectedStatusClasses(Set.of());
    forwarder.setMinimumConfidenceLevel(AuditIssueConfidence.CERTAIN);
    forwarder.setMinimumSeverityLevel(AuditIssueSeverity.HIGH);
  }

  @AfterEach
  void stop() {
    forwarder.extensionUnloaded();
    server.stop(0);
  }

  private Recorded take() throws InterruptedException {
    final Recorded post = posts.poll(5, TimeUnit.SECONDS);
    assertNotNull(post);
    return post;
  }

  @Test
  void siteMapIssueSendReportsHttpRejectionAndKeepsUtf8ContentType() throws Exception {
    serverStatus = 400;
    final CountDownLatch completed = new CountDownLatch(1);
    final AtomicReference<String> summary = new AtomicReference<>();
    try (var queue =
        new ManualSendQueue(
            message -> {
              summary.set(message);
              completed.countDown();
            })) {
      final var menu = new ShyHurricaneContextMenu(forwarder, queue);
      final var event =
          stub(
              AuditIssueContextMenuEvent.class,
              Map.of("selectedIssues", List.of(issue(List.of(), "évidence", ""))));
      SwingUtilities.invokeAndWait(
          () -> ((JMenuItem) menu.provideMenuItems(event).get(0)).doClick(0));
      assertTrue(completed.await(5, TimeUnit.SECONDS));
      assertTrue(summary.get().contains("0 sent, 0 skipped (no response), 1 failed, 0 dropped"));
      assertTrue(summary.get().contains("Server returned HTTP 400"));
      final Recorded post = take();
      assertEquals("/findings", post.path());
      assertEquals("application/json; charset=UTF-8", post.contentType());
      assertTrue(post.body().get("markdown").asText().contains("évidence"));
    }
  }

  @ParameterizedTest
  @ValueSource(ints = {100, 200, 302, 404, 503, 600})
  void manualHttpBypassesEveryFilterAndPreservesPayload(int status) throws Exception {
    final var message = message(request("héllo\u0000"), response(status, "binary\u0000é"));
    assertTrue(forwarder.sendRequestResponse(message));
    final Recorded post = take();
    assertEquals("/index", post.path());
    assertEquals("application/json; charset=UTF-8", post.contentType());
    assertEquals("POST", post.body().at("/request/method").asText());
    assertEquals("https://example.test/é", post.body().at("/request/endpoint").asText());
    assertEquals("héllo\u0000", post.body().at("/request/body").asText());
    assertEquals(status, post.body().at("/response/status_code").asInt());
    assertEquals("binary\u0000é", post.body().at("/response/body").asText());
    assertTrue(post.body().has("timestamp"));
    assertTrue(post.body().at("/request/headers").isObject());
    assertTrue(post.body().at("/response/headers").isObject());
  }

  @Test
  void requestWithoutResponseIsSkipped() throws Exception {
    assertFalse(forwarder.sendRequestResponse(message(request(""), null)));
    assertTrue(posts.isEmpty());
  }

  @Test
  void undecodableBodiesAreOmittedWithoutSkippingTheMessage() throws Exception {
    final HttpRequest badRequest =
        stub(
            HttpRequest.class,
            Map.of(
                "method",
                "GET",
                "url",
                "https://example.test",
                "headers",
                List.of(),
                "bodyToString",
                new IllegalArgumentException("bad body")));
    assertTrue(
        forwarder.sendRequestResponse(
            message(badRequest, response(200, new IllegalArgumentException("bad response")))));
    final Recorded post = take();
    assertFalse(post.body().get("request").has("body"));
    assertFalse(post.body().get("response").has("body"));
  }

  @Test
  void issuesBypassScopeSeverityAndConfidenceIncludingMissingEvidenceResponses() throws Exception {
    final var issue =
        issue(
            List.of(
                message(request("request evidence"), null),
                message(request("q".repeat(1100)), response(500, "r".repeat(1100)))),
            "details",
            "fix");
    forwarder.handleNewAuditIssue(issue);
    assertTrue(posts.isEmpty());
    forwarder.sendIssue(issue);
    final Recorded post = take();
    assertEquals("/findings", post.path());
    assertEquals("https://example.test/é", post.body().get("target").asText());
    assertEquals("Test issue at https://example.test/é", post.body().get("title").asText());
    final String markdown = post.body().get("markdown").asText();
    assertTrue(markdown.contains("INFORMATION"));
    assertTrue(markdown.contains("TENTATIVE"));
    assertTrue(markdown.contains("details"));
    assertTrue(markdown.contains("request evidence"));
    assertTrue(markdown.contains("500 Test"));
    assertTrue(markdown.contains("q".repeat(1024)));
    assertFalse(markdown.contains("q".repeat(1025)));
    assertTrue(markdown.contains("r".repeat(1024)));
    assertFalse(markdown.contains("r".repeat(1025)));
    assertTrue(markdown.contains("fix"));
  }

  @Test
  void issuesWithEmptyEvidenceAndBlankOptionalTextStillSend() throws Exception {
    forwarder.sendIssue(issue(List.of(), "", ""));
    assertEquals("/findings", take().path());
    forwarder.sendIssue(issue(List.of(message(request(""), response(200, ""))), "", ""));
    assertTrue(take().body().get("markdown").asText().contains("200 Test"));
  }

  @ParameterizedTest
  @ValueSource(ints = {302, 400, 500})
  void httpErrorsAndRedirectsAreFailuresAndDoNotPreventLaterSends(int status) throws Exception {
    serverStatus = status;
    final var message = message(request(""), response(200, ""));
    final IOException error =
        assertThrows(IOException.class, () -> forwarder.sendRequestResponse(message));
    assertTrue(error.getMessage().contains("HTTP " + status));
    take();
    assertTrue(posts.isEmpty(), "Redirects must not be followed");
    serverStatus = 200;
    assertTrue(forwarder.sendRequestResponse(message));
    take();
  }

  @Test
  void automaticHandlersStillApplyScopeContentAndIssueFiltersAndHandlePostFailures()
      throws Exception {
    forwarder.setSelectedStatusClasses(Set.of(2));
    forwarder.setAllTools(true);
    final HttpResponseReceived outOfScope =
        stub(
            HttpResponseReceived.class,
            Map.of("statusCode", (short) 200, "initiatingRequest", request("")));
    receive(outOfScope);
    assertTrue(posts.isEmpty());
    forwarder.setOnlyInScope(false);
    final HttpResponseReceived binary =
        stub(
            HttpResponseReceived.class,
            Map.of(
                "statusCode",
                (short) 200,
                "initiatingRequest",
                request(""),
                "headerValue",
                "application/octet-stream"));
    receive(binary);
    assertTrue(posts.isEmpty());

    forwarder.setMinimumConfidenceLevel(AuditIssueConfidence.TENTATIVE);
    final var issue = issue(List.of(), "", "");
    forwarder.handleNewAuditIssue(issue); // severity rejects it
    assertTrue(posts.isEmpty());
    forwarder.setMinimumSeverityLevel(AuditIssueSeverity.INFORMATION);
    forwarder.setOnlyInScope(true);
    forwarder.handleNewAuditIssue(issue); // no in-scope evidence
    forwarder.handleNewAuditIssue(issue(List.of(message(request(""), response(200, ""))), "", ""));
    assertTrue(posts.isEmpty());
    final HttpRequest inScope =
        stub(
            HttpRequest.class,
            Map.of(
                "isInScope",
                true,
                "method",
                "GET",
                "url",
                "https://example.test",
                "headers",
                List.of(),
                "bodyToString",
                ""));
    forwarder.handleNewAuditIssue(issue(List.of(message(inScope, response(200, ""))), "", ""));
    take();
    forwarder.setOnlyInScope(false);
    serverStatus = 500;
    forwarder.handleNewAuditIssue(issue);
    take();
    receive(
        stub(
            HttpResponseReceived.class,
            Map.of(
                "statusCode",
                (short) 200,
                "initiatingRequest",
                request(""),
                "headers",
                List.of(),
                "bodyToString",
                "")));
    take();
  }

  private void receive(HttpResponseReceived response) {
    try {
      forwarder.handleHttpResponseReceived(response);
    } catch (NullPointerException expected) {
      // The Montoya continueWith factory is only available inside Burp.
      assertTrue(
          java.util.Arrays.stream(expected.getStackTrace())
              .anyMatch(
                  frame ->
                      frame
                          .getClassName()
                          .equals("burp.api.montoya.http.handler.ResponseReceivedAction")));
    }
  }
}
