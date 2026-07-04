package com.relintio.agent;

public class WafResult {
    private final int score;
    private final String action;

    public WafResult(int score, String action) {
        this.score = score;
        this.action = action;
    }

    public int getScore() {
        return score;
    }

    public String getAction() {
        return action;
    }
}
