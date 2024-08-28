package com.ericsson.oss.services.scriptengine.rest.resources.scriptengine.application;

import com.ericsson.oss.services.scriptengine.rest.resources.GrammarRestResourceBean;
import com.ericsson.oss.services.scriptengine.rest.resources.file.FileRestResourceBean;
import com.ericsson.enm.cm.router.rest.CommandRouterApi;

import javax.ws.rs.ApplicationPath;
import javax.ws.rs.core.Application;
import java.util.HashSet;
import java.util.Set;

@ApplicationPath("/services")
public class ScriptEngineResourceMapper extends Application {
    private final Set<Object> resourceObjects = new HashSet<>();
    private final Set<Class<?>> resourceClasses = new HashSet<>();

    public ScriptEngineResourceMapper() {
        resourceClasses.add(CommandRouterApi.class);
        resourceClasses.add(FileRestResourceBean.class);
        resourceClasses.add(GrammarRestResourceBean.class);
    }

    @Override
    public Set<Class<?>> getClasses() {
        return resourceClasses;

    }

    @Override
    public Set<Object> getSingletons() {
        return resourceObjects;
    }
}
