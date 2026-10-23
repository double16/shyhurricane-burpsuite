package com.github.double16;

import static com.github.double16.ForwarderFixtures.*;
import static org.junit.jupiter.api.Assertions.*;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Registration;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import javax.swing.JMenuItem;
import javax.swing.SwingUtilities;
import org.junit.jupiter.api.Test;

class ForwarderLifecycleTest {
  @Test
  void registersMenuLoadsAndSavesSettingsAndDeregistersResourcesOnUnload() throws Exception {
    final var forwarder = new ExtensionShyHurricaneForwarder();
    final Map<String, Object> preferences = new HashMap<>();
    preferences.put("selectedToolsCsv", " PROXY, ,REPEATER ");
    preferences.put("onlyInScope", false);
    preferences.put("mcpServerUrl", "http://localhost:8001");
    preferences.put("minConfidence", "TENTATIVE");
    preferences.put("minSeverity", "HIGH");
    preferences.put("allTools", false);
    final AtomicReference<ContextMenuItemsProvider> provider = new AtomicReference<>();
    final AtomicInteger registered = new AtomicInteger();
    final AtomicInteger deregistered = new AtomicInteger();
    final CountDownLatch dropped = new CountDownLatch(1);
    final MontoyaApi api =
        (MontoyaApi)
            apiStub(MontoyaApi.class, preferences, provider, registered, deregistered, dropped);
    SwingUtilities.invokeAndWait(() -> forwarder.initialize(api));
    assertNotNull(provider.get());
    assertEquals(4, registered.get());
    assertFalse(forwarder.isOnlyInScope());
    assertFalse(forwarder.isAllTools());
    assertEquals(Set.of("PROXY", "REPEATER"), forwarder.getSelectedToolNames());
    assertEquals("http://localhost:8001", forwarder.getMcpServerUrl());
    assertEquals(AuditIssueConfidence.TENTATIVE, forwarder.getMinimumConfidenceLevel());
    assertEquals(AuditIssueSeverity.HIGH, forwarder.getMinimumSeverityLevel());
    forwarder.setOnlyInScope(true);
    forwarder.setAllTools(true);
    forwarder.setMcpServerUrl("http://localhost:8002");
    forwarder.setMinimumConfidenceLevel(AuditIssueConfidence.CERTAIN);
    forwarder.setMinimumSeverityLevel(AuditIssueSeverity.LOW);
    forwarder.setSelectedToolNames(Set.of("PROXY"));
    assertEquals("PROXY", preferences.get("selectedToolsCsv"));
    forwarder.setSelectedToolNames(null);
    assertEquals("", preferences.get("selectedToolsCsv"));
    forwarder.setSelectedStatusClasses(null);
    assertEquals("", preferences.get("selectedStatusClassesCsv"));
    assertEquals(true, preferences.get("onlyInScope"));
    assertEquals(true, preferences.get("allTools"));
    assertEquals("http://localhost:8002", preferences.get("mcpServerUrl"));
    assertEquals("CERTAIN", preferences.get("minConfidence"));
    assertEquals("LOW", preferences.get("minSeverity"));
    forwarder.extensionUnloaded();
    forwarder.extensionUnloaded();
    assertEquals(4, deregistered.get());
    final var event =
        stub(
            ContextMenuEvent.class,
            Map.of(
                "selectedIssues",
                java.util.List.of(),
                "selectedRequestResponses",
                java.util.List.of(message(request(""), null)),
                "messageEditorRequestResponse",
                Optional.empty()));
    SwingUtilities.invokeAndWait(
        () -> ((JMenuItem) provider.get().provideMenuItems(event).get(0)).doClick(0));
    assertTrue(dropped.await(5, TimeUnit.SECONDS));
  }

  private Object apiStub(
      Class<?> type,
      Map<String, Object> preferences,
      AtomicReference<ContextMenuItemsProvider> provider,
      AtomicInteger registered,
      AtomicInteger deregistered,
      CountDownLatch dropped) {
    return Proxy.newProxyInstance(
        type.getClassLoader(),
        new Class<?>[] {type},
        (proxy, method, args) -> {
          switch (method.getName()) {
            case "setName" -> {
              assertEquals("ShyHurricane", args[0]);
              return null;
            }
            case "registerUnloadingHandler" -> {
              return null;
            }
            case "registerContextMenuItemsProvider" ->
                provider.set((ContextMenuItemsProvider) args[0]);
            case "registerSuiteTab" -> {
              assertEquals("ShyHurricane", args[0]);
              assertTrue(SwingUtilities.isEventDispatchThread());
            }
            case "deregister" -> {
              deregistered.incrementAndGet();
              return null;
            }
            case "getString", "getBoolean" -> {
              return preferences.get(args[0]);
            }
            case "setString", "setBoolean" -> {
              preferences.put((String) args[0], args[1]);
              return null;
            }
            case "logToOutput" -> {
              assertTrue(((String) args[0]).contains("1 dropped"));
              dropped.countDown();
              return null;
            }
            default -> {}
          }
          if (method.getReturnType() == Registration.class) registered.incrementAndGet();
          if (method.getReturnType().isInterface()) {
            return apiStub(
                method.getReturnType(), preferences, provider, registered, deregistered, dropped);
          }
          return null;
        });
  }

  @Test
  void loadingWithoutInitializationKeepsDefaultsAndUnloadIsSafe() throws Exception {
    final var forwarder = new ExtensionShyHurricaneForwarder();
    final var load = ExtensionShyHurricaneForwarder.class.getDeclaredMethod("loadPrefs");
    load.setAccessible(true);
    load.invoke(forwarder);
    assertEquals("http://localhost:8000", forwarder.getMcpServerUrl());
    forwarder.extensionUnloaded();
  }
}
