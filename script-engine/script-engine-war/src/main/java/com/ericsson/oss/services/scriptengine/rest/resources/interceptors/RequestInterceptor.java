package com.ericsson.oss.services.scriptengine.rest.resources.interceptors;

import java.io.IOException;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import org.jboss.resteasy.annotations.interception.ServerInterceptor;
import org.jboss.resteasy.plugins.providers.multipart.InputPart;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Context;
import javax.ws.rs.ext.Provider;

@Provider
@ServerInterceptor
public class RequestInterceptor implements ContainerRequestFilter {
    @Context
    private HttpServletRequest request;

    @Override
    public void filter(ContainerRequestContext containerRequestContext) throws IOException {
        // @see TORF-36265 Spaces showing as unknown character in output of some CLI commands
        request.setAttribute(InputPart.DEFAULT_CONTENT_TYPE_PROPERTY,"text/plain; charset=UTF-8");
    }
}
