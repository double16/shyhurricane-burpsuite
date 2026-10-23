package com.github.double16;

import static com.github.double16.ForwarderFixtures.*;
import static org.junit.jupiter.api.Assertions.*;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.ui.contextmenu.*;
import java.awt.Component;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import javax.swing.JMenuItem;
import javax.swing.SwingUtilities;
import org.junit.jupiter.api.Test;

class ShyHurricaneContextMenuTest {
  private static ContextMenuEvent event(
      List<AuditIssue> issues,
      List<HttpRequestResponse> messages,
      Optional<MessageEditorHttpRequestResponse> editor) {
    return stub(
        ContextMenuEvent.class,
        Map.of(
            "selectedIssues",
            issues,
            "selectedRequestResponses",
            messages,
            "messageEditorRequestResponse",
            editor));
  }

  private static void click(List<Component> items) throws Exception {
    assertEquals(1, items.size());
    final JMenuItem item = (JMenuItem) items.get(0);
    assertEquals("Send", item.getText());
    SwingUtilities.invokeAndWait(() -> item.doClick(0));
  }

  @Test
  void hidesMenuForEmptySelectionsAndWebSockets() {
    try (var queue = new ManualSendQueue(message -> {})) {
      final var menu = new ShyHurricaneContextMenu(new ExtensionShyHurricaneForwarder(), queue);
      assertTrue(menu.provideMenuItems(event(List.of(), List.of(), Optional.empty())).isEmpty());
      assertTrue(
          menu.provideMenuItems(
                  stub(AuditIssueContextMenuEvent.class, Map.of("selectedIssues", List.of())))
              .isEmpty());
      assertTrue(menu.provideMenuItems(stub(WebSocketContextMenuEvent.class, Map.of())).isEmpty());
    }
  }

  @Test
  void sendsAllSelectedMessagesAndDoesNotAlsoSendEditorMessage() throws Exception {
    final List<HttpRequestResponse> sent = new ArrayList<>();
    final CountDownLatch completed = new CountDownLatch(1);
    final HttpRequestResponse first = message(request("first"), response(200, "ok"));
    final HttpRequestResponse second = message(request("second"), null);
    final var forwarder =
        new ExtensionShyHurricaneForwarder() {
          @Override
          boolean sendRequestResponse(HttpRequestResponse message) {
            assertFalse(SwingUtilities.isEventDispatchThread());
            sent.add(message);
            return true;
          }
        };
    try (var queue = new ManualSendQueue(summary -> completed.countDown())) {
      final var menu = new ShyHurricaneContextMenu(forwarder, queue);
      final List<HttpRequestResponse> selection = new ArrayList<>(List.of(first, second));
      final List<Component> items =
          menu.provideMenuItems(
              event(
                  List.of(),
                  selection,
                  Optional.of(stub(MessageEditorHttpRequestResponse.class, Map.of()))));
      selection.clear();
      click(items);
      assertTrue(completed.await(5, TimeUnit.SECONDS));
      assertEquals(2, sent.size());
      assertSame(first, sent.get(0));
      assertSame(second, sent.get(1));
    }
  }

  @Test
  void editorFallbackSendsCompleteMessageAndAllowsRepeatSends() throws Exception {
    final CountDownLatch completed = new CountDownLatch(2);
    final List<HttpRequestResponse> sent = new ArrayList<>();
    final var message = message(request("complete body"), response(200, "complete response"));
    final var forwarder =
        new ExtensionShyHurricaneForwarder() {
          @Override
          boolean sendRequestResponse(HttpRequestResponse value) {
            sent.add(value);
            return true;
          }
        };
    try (var queue = new ManualSendQueue(summary -> completed.countDown())) {
      final var menu = new ShyHurricaneContextMenu(forwarder, queue);
      final var items =
          menu.provideMenuItems(
              event(
                  List.of(),
                  List.of(),
                  Optional.of(
                      stub(
                          MessageEditorHttpRequestResponse.class,
                          Map.of("requestResponse", message)))));
      click(items);
      click(items);
      assertTrue(completed.await(5, TimeUnit.SECONDS));
      assertEquals(2, sent.size());
      assertSame(message, sent.get(0));
      assertSame(message, sent.get(1));
    }
  }

  @Test
  void issueSelectionsTakePrecedenceAndSupportBothEventTypes() throws Exception {
    final CountDownLatch completed = new CountDownLatch(2);
    final List<AuditIssue> sent = new ArrayList<>();
    final AuditIssue first = issue(List.of(), "", "");
    final AuditIssue second = issue(List.of(), "details", "fix");
    final var forwarder =
        new ExtensionShyHurricaneForwarder() {
          @Override
          void sendIssue(AuditIssue value) {
            sent.add(value);
          }

          @Override
          boolean sendRequestResponse(HttpRequestResponse value) {
            fail("Issue context must send only issues");
            return false;
          }
        };
    try (var queue = new ManualSendQueue(summary -> completed.countDown())) {
      final var menu = new ShyHurricaneContextMenu(forwarder, queue);
      click(
          menu.provideMenuItems(
              event(
                  List.of(first, second),
                  List.of(message(request(""), response(200, ""))),
                  Optional.empty())));
      click(
          menu.provideMenuItems(
              stub(AuditIssueContextMenuEvent.class, Map.of("selectedIssues", List.of(first)))));
      assertTrue(completed.await(5, TimeUnit.SECONDS));
      assertEquals(3, sent.size());
      assertSame(first, sent.get(0));
      assertSame(second, sent.get(1));
      assertSame(first, sent.get(2));
    }
  }
}
