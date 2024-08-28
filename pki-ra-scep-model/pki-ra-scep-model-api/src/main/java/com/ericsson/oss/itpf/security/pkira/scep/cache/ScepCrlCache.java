/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pkira.scep.cache;

import com.ericsson.oss.itpf.modeling.annotation.EModel;
import com.ericsson.oss.itpf.modeling.annotation.cache.*;
import com.ericsson.oss.itpf.security.pkira.scep.cdt.ScepCrl;

/**
 * This class defines model for CRLCache to store the CRL's for trusts.
 * 
 * @author xchowja
 * 
 */
@EModel(description = "This class defines the model for ScepCrlCache to store the CRLs", name = "ScepCrlCache")
@CacheDefinition(cacheMode = CacheMode.REPLICATED_SYNC, maxEntries = "1000", evictionStrategy = EvictionStrategy.LRU, keyClass = String.class, valueClass = ScepCrl.class)
public class ScepCrlCache {

}
