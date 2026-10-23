package com.github.double16;

import java.net.ConnectException;
import java.net.MalformedURLException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.util.Objects;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import javax.net.ssl.SSLException;

/** Bounded, short-lived retention of manually selected items, with one summary per selection. */
final class ManualSendQueue implements AutoCloseable {
  private final Consumer<String> output;
  private final ThreadPoolExecutor executor;

  ManualSendQueue(Consumer<String> output) {
    this.output = Objects.requireNonNull(output);
    executor =
        new ThreadPoolExecutor(
            1,
            1,
            0,
            TimeUnit.MILLISECONDS,
            new ArrayBlockingQueue<>(256),
            runnable -> {
              final Thread worker = new Thread(runnable, "ShyHurricane manual send");
              worker.setDaemon(true);
              return worker;
            });
  }

  Batch batch(int size) {
    return new Batch(size);
  }

  synchronized void submit(Batch batch, Send send) {
    final Item item = new Item(Objects.requireNonNull(batch), Objects.requireNonNull(send));
    if (executor.isShutdown()) {
      batch.complete(Outcome.DROPPED);
      return;
    }
    if (executor.getQueue().remainingCapacity() == 0) {
      final Item oldest = (Item) executor.getQueue().poll();
      if (oldest != null) {
        oldest.batch.complete(Outcome.DROPPED);
      }
    }
    executor.execute(item);
  }

  @Override
  public synchronized void close() {
    for (Runnable pending : executor.shutdownNow()) {
      ((Item) pending).batch.complete(Outcome.DROPPED);
    }
  }

  @FunctionalInterface
  interface Send {
    boolean send() throws Exception;
  }

  private enum Outcome {
    SENT,
    SKIPPED,
    FAILED,
    DROPPED
  }

  final class Batch {
    private int remaining;
    private final int[] counts = new int[Outcome.values().length];
    private String firstFailure;

    private Batch(int size) {
      if (size <= 0) {
        throw new IllegalArgumentException("A send batch must contain at least one item");
      }
      remaining = size;
    }

    private synchronized void complete(Outcome outcome) {
      counts[outcome.ordinal()]++;
      if (--remaining == 0) {
        output.accept(
            String.format(
                    "[ShyHurricane] Send: %d sent, %d skipped (no response), %d failed, %d dropped (queue full or unloaded).",
                    counts[0], counts[1], counts[2], counts[3])
                + (firstFailure == null ? "" : " First failure: " + firstFailure));
      }
    }

    private synchronized void failed(Exception failure) {
      if (firstFailure == null) {
        firstFailure = describeFailure(failure);
      }
      complete(Outcome.FAILED);
    }
  }

  private static String describeFailure(Exception failure) {
    // Do not include exception messages, URLs, response bodies, or issue contents.
    if (failure instanceof ExtensionShyHurricaneForwarder.PostFailureException post) {
      return "Server returned HTTP "
          + post.statusCode()
          + ". Check the server logs and endpoint compatibility.";
    }
    if (failure instanceof SocketTimeoutException) {
      return "Network timeout. Check server availability.";
    }
    if (failure instanceof ConnectException) {
      return "Connection failed. Check the configured server URL and whether the server is running.";
    }
    if (failure instanceof UnknownHostException) {
      return "Server hostname could not be resolved. Check the configured server URL and DNS.";
    }
    if (failure instanceof SSLException) {
      return "TLS connection failed. Check the server certificate and HTTPS configuration.";
    }
    if (failure instanceof MalformedURLException) {
      return "Invalid server URL. Configure an HTTP or HTTPS server URL.";
    }
    if (failure instanceof InterruptedException) {
      return "Send interrupted while unloading.";
    }
    final StackTraceElement[] trace = failure.getStackTrace();
    if (trace.length == 0) {
      return failure.getClass().getSimpleName() + ".";
    }
    final StackTraceElement location = trace[0];
    return failure.getClass().getSimpleName()
        + " at "
        + location.getClassName()
        + "."
        + location.getMethodName()
        + ":"
        + location.getLineNumber()
        + ".";
  }

  private final class Item implements Runnable {
    private final Batch batch;
    private final Send send;

    private Item(Batch batch, Send send) {
      this.batch = batch;
      this.send = send;
    }

    @Override
    public void run() {
      Outcome outcome;
      try {
        outcome = send.send() ? Outcome.SENT : Outcome.SKIPPED;
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        batch.failed(e);
        return;
      } catch (Exception e) {
        batch.failed(e);
        return;
      }
      batch.complete(outcome);
    }
  }
}
