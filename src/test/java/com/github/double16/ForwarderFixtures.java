package com.github.double16;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.issues.*;
import java.lang.reflect.Proxy;
import java.util.List;
import java.util.Map;

final class ForwarderFixtures {
  private ForwarderFixtures() {}

  static <T> T stub(Class<T> type, Map<String, ?> values) {
    return type.cast(
        Proxy.newProxyInstance(
            type.getClassLoader(),
            new Class<?>[] {type},
            (proxy, method, args) -> {
              final Object value = values.get(method.getName());
              if (value instanceof Exception exception) throw exception;
              if (value != null) return value;
              if (method.getReturnType() == boolean.class) return false;
              if (method.getReturnType() == int.class) return 0;
              return null;
            }));
  }

  static HttpRequest request(String body) {
    return stub(
        HttpRequest.class,
        Map.of(
            "method",
            "POST",
            "url",
            "https://example.test/é",
            "headers",
            List.of(),
            "bodyToString",
            body));
  }

  static HttpResponse response(int status, Object body) {
    return stub(
        HttpResponse.class,
        Map.of(
            "statusCode",
            (short) status,
            "reasonPhrase",
            "Test",
            "headers",
            List.of(),
            "bodyToString",
            body,
            "headerValue",
            "application/octet-stream"));
  }

  static HttpRequestResponse message(HttpRequest request, HttpResponse response) {
    return stub(
        HttpRequestResponse.class,
        response == null
            ? Map.of("request", request)
            : Map.of("request", request, "response", response, "hasResponse", true));
  }

  static AuditIssue issue(List<HttpRequestResponse> evidence, String detail, String remediation) {
    return stub(
        AuditIssue.class,
        Map.of(
            "name",
            "Test issue",
            "baseUrl",
            "https://example.test/é",
            "severity",
            AuditIssueSeverity.INFORMATION,
            "confidence",
            AuditIssueConfidence.TENTATIVE,
            "detail",
            detail,
            "remediation",
            remediation,
            "requestResponses",
            evidence,
            "definition",
            stub(
                AuditIssueDefinition.class,
                Map.of("background", "Background", "remediation", remediation))));
  }
}
