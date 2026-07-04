package com.relintio.agent;

public class AgentConfig {
    private final String licenseKey;
    private final String apiUrl;
    private final int syncIntervalSeconds;

    public AgentConfig(String licenseKey) {
        this(licenseKey, "https://api.relintio.com/api", 60);
    }

    public AgentConfig(String licenseKey, String apiUrl, int syncIntervalSeconds) {
        this.licenseKey = licenseKey;
        this.apiUrl = apiUrl;
        this.syncIntervalSeconds = syncIntervalSeconds;
    }

    public String getLicenseKey() {
        return licenseKey;
    }

    public String getApiUrl() {
        return apiUrl;
    }

    public int getSyncIntervalSeconds() {
        return syncIntervalSeconds;
    }
}
