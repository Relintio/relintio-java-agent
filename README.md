# Relintio WAF Protection Agent SDK (Java)

Official Jakarta Servlet Filter WAF agent SDK for Java. Compatible with Java 11+ and Spring Boot 3+.

## Installation

Add the dependency to your `pom.xml`:

```xml
<dependency>
    <groupId>com.relintio</groupId>
    <artifactId>relintio-agent</artifactId>
    <version>0.1.0</version>
</dependency>
```

Or for Gradle:

```groovy
implementation 'com.relintio:relintio-agent:0.1.0'
```

## Features

- **Jakarta Servlet Filter:** Modern Jakarta EE 9/10/11 Filter for easy web integration.
- **Dependency-Free Core:** Avoids classpath collision by keeping the SDK dependency-free (no external HTTP clients or JSON dependencies).
- **Background Synchronization:** Periodically pulls rules from the Relintio console asynchronously.

## Usage

### 1. Spring Boot Integration

To register the Relintio WAF Filter in your Spring Boot application, define a `FilterRegistrationBean` inside a configuration class:

```java
package com.example.demo;

import com.relintio.agent.Agent;
import com.relintio.agent.AgentConfig;
import com.relintio.agent.RelintioFilter;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SecurityConfig {

    @Bean
    public FilterRegistrationBean<RelintioFilter> relintioFilter() {
        // 1. Configure the Relintio Agent
        AgentConfig config = new AgentConfig(
            "YOUR_LICENSE_KEY",
            "https://api.relintio.com/api",
            60 // Rules sync interval in seconds
        );

        Agent agent = new Agent(config);
        agent.startSync(); // Start background rule syncer

        // 2. Register the Jakarta Servlet Filter
        FilterRegistrationBean<RelintioFilter> registrationBean = new FilterRegistrationBean<>();
        registrationBean.setFilter(new RelintioFilter(agent));
        registrationBean.addUrlPatterns("/*");
        registrationBean.setOrder(1); // Set to run first in filter chain

        return registrationBean;
    }
}
```
