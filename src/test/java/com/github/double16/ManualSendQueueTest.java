package com.github.double16;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.net.ConnectException;
import java.net.MalformedURLException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;
import javax.net.ssl.SSLException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class ManualSendQueueTest {
  static Stream<Arguments> failures() {
    final IOException withoutTrace = new IOException("secret");
    withoutTrace.setStackTrace(new StackTraceElement[0]);
    return Stream.of(
        Arguments.of(
            new ExtensionShyHurricaneForwarder.PostFailureException(400),
            "Server returned HTTP 400"),
        Arguments.of(new SocketTimeoutException("secret"), "Network timeout"),
        Arguments.of(new ConnectException("secret"), "Connection failed"),
        Arguments.of(new UnknownHostException("secret"), "Server hostname could not be resolved"),
        Arguments.of(new SSLException("secret"), "TLS connection failed"),
        Arguments.of(new MalformedURLException("secret"), "Invalid server URL"),
        Arguments.of(new InterruptedException("secret"), "Send interrupted"),
        Arguments.of(new NullPointerException("secret"), "NullPointerException at"),
        Arguments.of(withoutTrace, "IOException."));
  }

  @ParameterizedTest
  @MethodSource("failures")
  void reportsSafeFailureDetailsAndPreservesTheFirstFailure(Exception failure, String expected)
      throws Exception {
    final CountDownLatch completed = new CountDownLatch(1);
    final AtomicReference<String> summary = new AtomicReference<>();
    try (var queue =
        new ManualSendQueue(
            message -> {
              summary.set(message);
              completed.countDown();
            })) {
      final var batch = queue.batch(2);
      queue.submit(
          batch,
          () -> {
            throw failure;
          });
      queue.submit(
          batch,
          () -> {
            throw new IOException("later secret");
          });
      await(completed);
      assertTrue(summary.get().contains("2 failed"));
      assertTrue(summary.get().contains("First failure: " + expected));
      assertFalse(summary.get().contains("secret"));
    }
  }

  private static void await(CountDownLatch latch) throws InterruptedException {
    assertTrue(latch.await(5, TimeUnit.SECONDS), "Background operation did not complete");
  }

  @Test
  void reportsAllOutcomesAndContinuesAfterFailureOffCallingThread() throws Exception {
    final CountDownLatch completed = new CountDownLatch(1);
    final AtomicReference<String> summary = new AtomicReference<>();
    final Thread caller = Thread.currentThread();
    try (var queue =
        new ManualSendQueue(
            message -> {
              summary.set(message);
              completed.countDown();
            })) {
      assertThrows(IllegalArgumentException.class, () -> queue.batch(0));
      final var batch = queue.batch(3);
      queue.submit(
          batch,
          () -> {
            throw new IOException("secret URL must not appear");
          });
      queue.submit(batch, () -> false);
      queue.submit(
          batch,
          () -> {
            assertNotSame(caller, Thread.currentThread());
            return true;
          });
      await(completed);
      assertTrue(summary.get().contains("1 sent, 1 skipped (no response), 1 failed, 0 dropped"));
      assertFalse(summary.get().contains("secret"));
    }
  }

  @Test
  void dropsOldestPendingItemWhenQueueIsFull() throws Exception {
    final CountDownLatch started = new CountDownLatch(1);
    final CountDownLatch release = new CountDownLatch(1);
    final CountDownLatch completed = new CountDownLatch(1);
    final AtomicReference<String> summary = new AtomicReference<>();
    final AtomicBoolean oldestRan = new AtomicBoolean();
    try (var queue =
        new ManualSendQueue(
            message -> {
              summary.set(message);
              completed.countDown();
            })) {
      final var batch = queue.batch(258);
      queue.submit(
          batch,
          () -> {
            started.countDown();
            await(release);
            return true;
          });
      await(started);
      queue.submit(
          batch,
          () -> {
            oldestRan.set(true);
            return true;
          });
      for (int i = 0; i < 256; i++) queue.submit(batch, () -> true);
      release.countDown();
      await(completed);
      assertFalse(oldestRan.get());
      assertTrue(summary.get().contains("257 sent, 0 skipped (no response), 0 failed, 1 dropped"));
    } finally {
      release.countDown();
    }
  }

  @Test
  void unloadInterruptsActiveWorkDiscardsPendingWorkAndRejectsLaterSubmissions() throws Exception {
    final CountDownLatch started = new CountDownLatch(1);
    final CountDownLatch completed = new CountDownLatch(1);
    final AtomicReference<String> summary = new AtomicReference<>();
    final AtomicBoolean pendingRan = new AtomicBoolean();
    final var queue =
        new ManualSendQueue(
            message -> {
              summary.set(message);
              completed.countDown();
            });
    final var batch = queue.batch(3);
    queue.submit(
        batch,
        () -> {
          started.countDown();
          new CountDownLatch(1).await();
          return true;
        });
    await(started);
    queue.submit(
        batch,
        () -> {
          pendingRan.set(true);
          return true;
        });
    queue.close();
    queue.close();
    queue.submit(
        batch,
        () -> {
          pendingRan.set(true);
          return true;
        });
    await(completed);
    assertFalse(pendingRan.get());
    assertTrue(summary.get().contains("0 sent, 0 skipped (no response), 1 failed, 2 dropped"));
  }
}
