package com.ericsson.oss.services.cm.scriptengine.ejb.service.stubunittest;

import java.io.Serializable;
import java.util.Map;

import com.ericsson.oss.itpf.sdk.context.ContextService;
import com.ericsson.oss.services.cm.scriptengine.ejb.service.stubs.FileDownloadHandlerImpl;

/*
 * ensure this class names ends in Test so it does NOT get included in the ear
 * which would lead to an Ambiguous dependency with the real ContextService
 */
public class ContextServiceStubForUnitTest implements ContextService {

    public String userId = FileDownloadHandlerImpl.AUTHENTICATED_USER_ID;

    @Override
    public void setContextValue(final String contextParameterName, final Serializable contextData) {
        // Not required for this test
    }

    @Override
    public <T> T getContextValue(final String contextParameterName) {
        return (T) userId;
    }

    @Override
    public Map<String, Serializable> getContextData() {
        // Not required for this test
        return null;
    }
}