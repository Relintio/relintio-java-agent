package com.relintio.agent;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import java.lang.reflect.Field;
import java.util.List;

public class AgentTest {

    @Test
    public void testBasicWafMatch() throws Exception {
        AgentConfig config = new AgentConfig("test_license_key");
        Agent agent = new Agent(config);

        // Inject rule reflectively to test matching engine
        Field rulesField = Agent.class.getDeclaredField("rules");
        rulesField.setAccessible(true);
        @SuppressWarnings("unchecked")
        List<WafRule> rulesList = (List<WafRule>) rulesField.get(agent);

        rulesList.add(new WafRule("path", "/admin", "contains", 60, "challenge"));

        WafResult result = agent.checkRequest("127.0.0.1", "Mozilla", "/admin/settings");
        assertEquals(60, result.getScore());
        assertEquals("challenge", result.getAction());

        agent.deinit();
    }
}
