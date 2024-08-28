/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2015
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pkimanager.webcli.cache;

import com.ericsson.oss.itpf.modeling.annotation.EModel;
import com.ericsson.oss.itpf.modeling.annotation.cache.*;

@EModel(description = "Provides Service to keep PkiWebCli content in cache", name = "PkiWebCliExportCache")
@CacheDefinition(cacheMode = CacheMode.DISTRIBUTED_SYNC, maxEntries = "100", evictionStrategy = EvictionStrategy.LRU, timeToLive = 3000000, keyClass = String.class, valueClass = Object.class)
public class PkiWebCliExportCache {

}
