package com.relintio.agent;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

public class RelintioFilter implements Filter {
    private Agent agent;

    public RelintioFilter() {}

    public RelintioFilter(Agent agent) {
        this.agent = agent;
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        if (this.agent == null) {
            String licenseKey = filterConfig.getInitParameter("licenseKey");
            String apiUrl = filterConfig.getInitParameter("apiUrl");
            if (licenseKey == null || licenseKey.isEmpty()) {
                throw new ServletException("RelintioFilter init-param 'licenseKey' is required.");
            }
            AgentConfig config = (apiUrl == null || apiUrl.isEmpty()) 
                    ? new AgentConfig(licenseKey) 
                    : new AgentConfig(licenseKey, apiUrl, 60);
            
            this.agent = new Agent(config);
            this.agent.startSync();
        }
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        if (request instanceof HttpServletRequest && response instanceof HttpServletResponse) {
            HttpServletRequest req = (HttpServletRequest) request;
            HttpServletResponse res = (HttpServletResponse) response;

            String ip = getClientIp(req);
            String userAgent = req.getHeader("User-Agent");
            if (userAgent == null) userAgent = "";
            String path = req.getRequestURI();

            WafResult result = agent.checkRequest(ip, userAgent, path);
            agent.sendTelemetry(ip, userAgent, path, result);

            if ("block".equalsIgnoreCase(result.getAction())) {
                res.setStatus(403);
                res.setContentType("application/json");
                res.getWriter().write("{\"error\":\"Request blocked by security policy.\"}");
                return;
            } else if ("challenge".equalsIgnoreCase(result.getAction())) {
                res.setStatus(401);
                res.setContentType("application/json");
                res.getWriter().write("{\"error\":\"Security challenge verification required.\"}");
                return;
            }
        }
        chain.doFilter(request, response);
    }

    @Override
    public void destroy() {
        if (this.agent != null) {
            this.agent.deinit();
        }
    }

    private String getClientIp(HttpServletRequest request) {
        String xff = request.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isEmpty()) {
            return xff.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
