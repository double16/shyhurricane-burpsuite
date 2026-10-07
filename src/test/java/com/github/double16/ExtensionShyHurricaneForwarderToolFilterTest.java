package com.github.double16;

import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class ExtensionShyHurricaneForwarderToolFilterTest {

    // Simple HTTP server to capture outgoing POSTs
    private static class RecordingServer implements HttpHandler, AutoCloseable {
        HttpServer server;
        volatile String lastPath;
        volatile String lastBody;
        volatile int requestCount;

        RecordingServer() throws IOException {
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/", this);
            server.setExecutor(null);
            server.start();
        }

        String baseUrl() {
            return "http://127.0.0.1:" + server.getAddress().getPort();
        }

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            lastPath = exchange.getRequestURI().getPath();
            lastBody = readAll(exchange.getRequestBody());
            requestCount++;
            byte[] ok = "OK".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, ok.length);
            exchange.getResponseBody().write(ok);
            exchange.close();
        }

        private static String readAll(InputStream in) throws IOException {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }

        @Override
        public void close() {
            if (server != null) server.stop(0);
        }
    }

    private ExtensionShyHurricaneForwarder ext;
    private RecordingServer server;

    @BeforeEach
    void setUp() throws Exception {
        ext = new ExtensionShyHurricaneForwarder();
        server = new RecordingServer();
        ext.setMcpServerUrl(server.baseUrl());
        // Avoid scope dependency in tests
        ext.setOnlyInScope(false);
    }

    @AfterEach
    void tearDown() {
        server.close();
    }

    private static HttpRequest reqProxy(boolean inScope) {
        InvocationHandler h = (proxy, method, args) -> switch (method.getName()) {
            case "isInScope" -> inScope;
            case "method" -> "GET";
            case "url" -> "https://example.com";
            case "headers" -> List.<HttpHeader>of();
            case "bodyToString" -> "";
            default -> defaultReturn(method);
        };
        return (HttpRequest) Proxy.newProxyInstance(
                HttpRequest.class.getClassLoader(), new Class[]{HttpRequest.class}, h);
    }

    private static Object defaultReturn(Method m) {
        Class<?> rt = m.getReturnType();
        if (!rt.isPrimitive()) return null;
        if (rt == boolean.class) return false;
        if (rt == byte.class) return (byte) 0;
        if (rt == short.class) return (short) 0;
        if (rt == int.class) return 0;
        if (rt == long.class) return 0L;
        if (rt == float.class) return 0f;
        if (rt == double.class) return 0d;
        if (rt == char.class) return (char) 0;
        return null;
    }

    private static Object toolSourceProxy(ToolType toolType) {
        // Interface is burp.api.montoya.core.ToolSource
        ClassLoader cl = ToolType.class.getClassLoader();
        try {
            Class<?> toolSourceIface = Class.forName("burp.api.montoya.core.ToolSource", false, cl);
            InvocationHandler h = (proxy, method, args) -> {
                if ("toolType".equals(method.getName())) {
                    return toolType;
                }
                return defaultReturn(method);
            };
            return Proxy.newProxyInstance(cl, new Class[]{toolSourceIface}, h);
        } catch (ClassNotFoundException e) {
            throw new AssertionError("ToolSource interface not found", e);
        }
    }

    private static HttpResponseReceived responseProxy(Object toolSource, String contentType,
                                                      int statusCode, String body, HttpRequest req) {
        InvocationHandler h = (proxy, method, args) -> switch (method.getName()) {
            case "toolSource" -> toolSource;
            case "initiatingRequest" -> req;
            case "headers" -> List.<HttpHeader>of();
            case "headerValue" -> args != null && args.length == 1 && "Content-Type".equalsIgnoreCase(String.valueOf(args[0]))
                    ? contentType : null;
            case "statusCode" -> (short) statusCode;
            case "bodyToString" -> body;
            default -> defaultReturn(method);
        };
        return (HttpResponseReceived) Proxy.newProxyInstance(
                HttpResponseReceived.class.getClassLoader(), new Class[]{HttpResponseReceived.class}, h);
    }

    @Test
    @DisplayName("When allTools=false and tool not selected/null, response is not forwarded")
    void blockedWhenToolNotSelected() {
        // Configure to require explicit tools but select none
        ext.setAllTools(false);
        ext.setSelectedToolNames(java.util.Set.of());

        // toolSource is null here → should be blocked by filter
        HttpResponseReceived resp = responseProxy(null, "text/html", 200, "ok", reqProxy(true));

        try {
            ext.handleHttpResponseReceived(resp);
        } catch (NullPointerException expected) {
            // Burp Montoya's ResponseReceivedAction.continueWith requires internal factory; ignore in unit tests
        }

        assertEquals(0, server.requestCount, "No POST should be made when tool is not selected");
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 99, 100, 101, 199, 200, 204, 299, 300, 399, 400, 499, 500, 599, 600})
    void defaultStatusFilter(int status) {
        receiveStatus(status);
        assertEquals(status >= 200 && status <= 299 ? 1 : 0, server.requestCount);
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 100, 101, 199, 200, 299, 300, 399, 400, 499, 500, 599, 600})
    void allStatusesStillExcludeInformationalAndInvalidCodes(int status) {
        ext.setSelectedStatusClasses(java.util.Set.of(2, 3, 4, 5));
        receiveStatus(status);
        assertEquals(status >= 200 && status <= 599 ? 1 : 0, server.requestCount);
    }

    @ParameterizedTest
    @ValueSource(ints = {2, 3, 4, 5})
    void individualStatusClasses(int selectedClass) {
        ext.setSelectedStatusClasses(java.util.Set.of(selectedClass));
        for (int statusClass = 2; statusClass <= 5; statusClass++) {
            int before = server.requestCount;
            receiveStatus(statusClass * 100);
            assertEquals(statusClass == selectedClass ? 1 : 0, server.requestCount - before);
        }
    }

    @Test
    void combinedAndEmptyStatusSelections() {
        ext.setSelectedStatusClasses(java.util.Set.of(3, 5));
        for (int status : new int[]{200, 300, 400, 500}) receiveStatus(status);
        assertEquals(2, server.requestCount);
        ext.setSelectedStatusClasses(java.util.Set.of());
        for (int status : new int[]{200, 300, 400, 500}) receiveStatus(status);
        assertEquals(2, server.requestCount);
    }

    private void receiveStatus(int status) {
        try {
            ext.handleHttpResponseReceived(responseProxy(null, "text/html", status, "ok", reqProxy(true)));
        } catch (NullPointerException expected) {
            // Montoya's continueWith factory is unavailable outside Burp.
            assertTrue(java.util.Arrays.stream(expected.getStackTrace())
                    .anyMatch(frame -> frame.getClassName().equals(
                            "burp.api.montoya.http.handler.ResponseReceivedAction")));
        }
    }

    @Test
    @DisplayName("When allTools=false and tool is selected, response is forwarded to /index")
    void allowedWhenToolSelected() throws Exception {
        // Pick a real ToolType value at runtime to avoid assuming specific enums
        ToolType chosen = ToolType.values()[0];
        ext.setAllTools(false);
        ext.setSelectedToolNames(java.util.Set.of(chosen.name()));

        Object toolSrc = toolSourceProxy(chosen);

        // content-type text/html should not be skipped by shouldSkip
        HttpResponseReceived resp = responseProxy(toolSrc, "text/html", 200, "<html></html>", reqProxy(true));

        try {
            ext.handleHttpResponseReceived(resp);
        } catch (NullPointerException expected) {
            // See comment in the other test: ignore NPE from Montoya internals
        }

        assertEquals(1, server.requestCount, "Expected one POST to /index");
        assertEquals("/index", server.lastPath);

        // Check payload is JSON with expected keys
        ObjectMapper mapper = new ObjectMapper();
        @SuppressWarnings("unchecked")
        Map<String, Object> json = mapper.readValue(server.lastBody, Map.class);
        assertTrue(json.containsKey("timestamp"));
        assertTrue(json.containsKey("request"));
        assertTrue(json.containsKey("response"));
    }
}
