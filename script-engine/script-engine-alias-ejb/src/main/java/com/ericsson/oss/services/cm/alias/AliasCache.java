package com.ericsson.oss.services.cm.alias;

import javax.cache.Cache;
import javax.inject.Inject;

import com.ericsson.oss.itpf.sdk.cache.annotation.NamedCache;
import com.ericsson.oss.services.cli.alias.model.CliAlias;

/**
 * Modeled local cache to store {@link CliAlias} objects.
 * This cache is not distributed or persisted and will lose its contents if VM is halted.
 */
public class AliasCache {

    @Inject
    @NamedCache("CliAliasCache")
    private Cache<String, CliAlias> cliAliasCache;

    public void addCliAlias(final CliAlias cliAlias) {
        cliAliasCache.put(cliAlias.name, cliAlias);
    }

    public CliAlias getCliAlias(final String aliasName) {
        return cliAliasCache.get(aliasName);
    }
}
