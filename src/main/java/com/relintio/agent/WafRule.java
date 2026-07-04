package com.relintio.agent;

public class WafRule {
    private final String type;
    private final String pattern;
    private final String condition;
    private final int score;
    private final String action;

    public WafRule(String type, String pattern, String condition, int score, String action) {
        this.type = type;
        this.pattern = pattern;
        this.condition = condition;
        this.score = score;
        this.action = action;
    }

    public String getType() {
        return type;
    }

    public String getPattern() {
        return pattern;
    }

    public String getCondition() {
        return condition;
    }

    public int getScore() {
        return score;
    }

    public String getAction() {
        return action;
    }
}
