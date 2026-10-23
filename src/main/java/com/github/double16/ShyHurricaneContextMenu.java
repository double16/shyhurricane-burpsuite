package com.github.double16;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.ui.contextmenu.AuditIssueContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import java.awt.Component;
import java.util.List;
import java.util.Objects;
import javax.swing.JMenuItem;

final class ShyHurricaneContextMenu implements ContextMenuItemsProvider {
  private final ExtensionShyHurricaneForwarder forwarder;
  private final ManualSendQueue queue;

  ShyHurricaneContextMenu(ExtensionShyHurricaneForwarder forwarder, ManualSendQueue queue) {
    this.forwarder = Objects.requireNonNull(forwarder);
    this.queue = Objects.requireNonNull(queue);
  }

  @Override
  public List<Component> provideMenuItems(AuditIssueContextMenuEvent event) {
    return issueMenu(List.copyOf(event.selectedIssues()));
  }

  @Override
  public List<Component> provideMenuItems(ContextMenuEvent event) {
    final List<AuditIssue> issues = List.copyOf(event.selectedIssues());
    if (!issues.isEmpty()) {
      return issueMenu(issues);
    }
    final List<HttpRequestResponse> selected = List.copyOf(event.selectedRequestResponses());
    final List<HttpRequestResponse> messages =
        selected.isEmpty()
            ? event
                .messageEditorRequestResponse()
                .map(editor -> List.of(editor.requestResponse()))
                .orElse(List.of())
            : selected;
    if (messages.isEmpty()) {
      return List.of();
    }
    return menu(
        () -> {
          final ManualSendQueue.Batch batch = queue.batch(messages.size());
          for (HttpRequestResponse message : messages) {
            // Montoya HTTP messages are immutable; retain only until this bounded task runs.
            queue.submit(batch, () -> forwarder.sendRequestResponse(message));
          }
        });
  }

  private List<Component> issueMenu(List<AuditIssue> issues) {
    if (issues.isEmpty()) {
      return List.of();
    }
    return menu(
        () -> {
          final ManualSendQueue.Batch batch = queue.batch(issues.size());
          for (AuditIssue issue : issues) {
            queue.submit(
                batch,
                () -> {
                  forwarder.sendIssue(issue);
                  return true;
                });
          }
        });
  }

  private List<Component> menu(Runnable send) {
    final JMenuItem item = new JMenuItem("Send");
    item.addActionListener(event -> send.run());
    return List.of(item);
  }
}
