package com.relintio.agent;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Agent {
    private static final String AGENT_VERSION = "0.1.4";
    private final AgentConfig config;
    private final HttpClient httpClient;
    private final List<WafRule> rules;
    private final ScheduledExecutorService scheduler;
    private final ExecutorService telemetryExecutor;
    private final Object rulesLock = new Object();
    private final AtomicBoolean started = new AtomicBoolean();

    public Agent(AgentConfig config) {
        this.config = config;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();
        this.rules = new ArrayList<>();
        this.scheduler = Executors.newSingleThreadScheduledExecutor(runnable -> {
            Thread thread = new Thread(runnable, "relintio-rules-syncer");
            thread.setDaemon(true);
            return thread;
        });
        this.telemetryExecutor = Executors.newSingleThreadExecutor(runnable -> {
            Thread thread = new Thread(runnable, "relintio-telemetry");
            thread.setDaemon(true);
            return thread;
        });
    }

    public void startSync() {
        if (started.compareAndSet(false, true)) {
            scheduler.scheduleWithFixedDelay(this::syncRules, 0, Math.max(1, config.getSyncIntervalSeconds()), TimeUnit.SECONDS);
        }
    }

    public void deinit() {
        scheduler.shutdown();
        telemetryExecutor.shutdown();
        try {
            if (!scheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                scheduler.shutdownNow();
            }
            if (!telemetryExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                telemetryExecutor.shutdownNow();
            }
        } catch (InterruptedException e) {
            scheduler.shutdownNow();
            telemetryExecutor.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }

    public void syncRules() {
        try {
            String payload = String.format(
                    "{\"license_key\":\"%s\",\"domain\":\"%s\",\"protocol_version\":1,\"agent_kind\":\"java\",\"agent_version\":\"%s\",\"capabilities\":[\"custom_rules\",\"telemetry\"]}",
                    escapeJson(config.getLicenseKey()), escapeJson(config.getDomain()), AGENT_VERSION
            );
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(apiEndpoint("/agent/verify")))
                    .timeout(Duration.ofSeconds(10))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(payload))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() == 200) {
                List<WafRule> newRules = parseRulesJson(response.body());
                synchronized (rulesLock) {
                    rules.clear();
                    rules.addAll(newRules);
                }
            }
        } catch (Exception e) {
            // Silence exceptions in background rules syncing
        }
    }

    public WafResult checkRequest(String ip, String userAgent, String path) {
        int score = 0;
        String action = "allow";

        List<WafRule> currentRules;
        synchronized (rulesLock) {
            currentRules = new ArrayList<>(rules);
        }

        for (WafRule rule : currentRules) {
            boolean matched = false;
            String checkValue = null;

            if ("ip".equalsIgnoreCase(rule.getType())) {
                checkValue = ip;
            } else if ("user_agent".equalsIgnoreCase(rule.getType())) {
                checkValue = userAgent;
            } else if ("path".equalsIgnoreCase(rule.getType())) {
                checkValue = path;
            }

            if (checkValue != null) {
                matched = matchValue(checkValue, rule.getPattern(), rule.getCondition());
            }

            if (matched) {
                score += rule.getScore();
                if ("block".equalsIgnoreCase(rule.getAction())) {
                    action = "block";
                } else if ("challenge".equalsIgnoreCase(rule.getAction()) && !"block".equalsIgnoreCase(action)) {
                    action = "challenge";
                }
            }
        }

        if (score >= 100) {
            action = "block";
        } else if (score >= 50 && !"block".equalsIgnoreCase(action)) {
            action = "challenge";
        }

        return new WafResult(score, action);
    }

    public void sendTelemetry(String ip, String userAgent, String path, WafResult result) {
        if (telemetryExecutor.isShutdown()) {
            return;
        }

        // Run telemetry log asynchronously to avoid blocking request response pipelines
        telemetryExecutor.submit(() -> {
            try {
                String payload = String.format(
                        "{\"license_key\":\"%s\",\"ip\":\"%s\",\"user_agent\":\"%s\",\"path\":\"%s\",\"risk_score\":%d,\"action\":\"%s\",\"reason_code\":\"sdk_rule\",\"protocol_version\":1,\"agent_kind\":\"java\",\"agent_version\":\"%s\"}",
                        escapeJson(config.getLicenseKey()),
                        escapeJson(ip), escapeJson(userAgent), escapeJson(path),
                        Math.max(0, Math.min(100, result.getScore())), result.getAction().toUpperCase(), AGENT_VERSION
                );

                HttpRequest request = HttpRequest.newBuilder()
                        .uri(URI.create(apiEndpoint("/agent/log")))
                        .timeout(Duration.ofSeconds(10))
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(payload))
                        .build();

                httpClient.send(request, HttpResponse.BodyHandlers.discarding());
            } catch (Exception e) {
                // Ignore telemetry post exceptions
            }
        });
    }

    private boolean matchValue(String val, String pattern, String condition) {
        if ("equals".equalsIgnoreCase(condition)) {
            return val.equalsIgnoreCase(pattern);
        } else if ("contains".equalsIgnoreCase(condition)) {
            return val.toLowerCase().contains(pattern.toLowerCase());
        }
        return val.toLowerCase().contains(pattern.toLowerCase());
    }

    private String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\b", "\\b")
                .replace("\f", "\\f")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    private String apiEndpoint(String path) {
        return config.getApiUrl().replaceAll("/+$", "") + path;
    }

    private List<WafRule> parseRulesJson(String body) {
        List<WafRule> list = new ArrayList<>();
        // Simple manual JSON regex parser to avoid external dependencies
        Pattern pattern = Pattern.compile("\\{\\s*\"type\"\\s*:\\s*\"([^\"]+)\"\\s*,\\s*\"pattern\"\\s*:\\s*\"([^\"]+)\"\\s*,\\s*\"condition\"\\s*:\\s*\"([^\"]+)\"\\s*,\\s*\"score\"\\s*:\\s*(\\d+)\\s*,\\s*\"action\"\\s*:\\s*\"([^\"]+)\"\\s*\\}");
        Matcher matcher = pattern.matcher(body);
        while (matcher.find()) {
            String type = matcher.group(1);
            String rulePattern = matcher.group(2);
            String condition = matcher.group(3);
            int score = Integer.parseInt(matcher.group(4));
            String action = matcher.group(5);
            list.add(new WafRule(type, rulePattern, condition, score, action));
        }
        return list;
    }
}
