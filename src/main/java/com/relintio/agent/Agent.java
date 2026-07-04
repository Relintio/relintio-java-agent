package com.relintio.agent;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Agent {
    private final AgentConfig config;
    private final HttpClient httpClient;
    private final List<WafRule> rules;
    private final ScheduledExecutorService scheduler;
    private final Object rulesLock = new Object();

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
    }

    public void startSync() {
        scheduler.scheduleAtFixedRate(this::syncRules, 0, config.getSyncIntervalSeconds(), TimeUnit.SECONDS);
    }

    public void deinit() {
        scheduler.shutdown();
        try {
            if (!scheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                scheduler.shutdownNow();
            }
        } catch (InterruptedException e) {
            scheduler.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }

    public void syncRules() {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(config.getApiUrl() + "/rules/sync"))
                    .timeout(Duration.ofSeconds(10))
                    .header("Authorization", "Bearer " + config.getLicenseKey())
                    .GET()
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
        // Run telemetry log asynchronously to avoid blocking request response pipelines
        Executors.newSingleThreadExecutor().submit(() -> {
            try {
                String payload = String.format(
                        "{\"ip\":\"%s\",\"user_agent\":\"%s\",\"path\":\"%s\",\"score\":%d,\"action\":\"%s\",\"timestamp\":%d}",
                        escapeJson(ip), escapeJson(userAgent), escapeJson(path),
                        result.getScore(), result.getAction(), System.currentTimeMillis() / 1000
                );

                HttpRequest request = HttpRequest.newBuilder()
                        .uri(URI.create(config.getApiUrl() + "/telemetry/log"))
                        .timeout(Duration.ofSeconds(10))
                        .header("Authorization", "Bearer " + config.getLicenseKey())
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
