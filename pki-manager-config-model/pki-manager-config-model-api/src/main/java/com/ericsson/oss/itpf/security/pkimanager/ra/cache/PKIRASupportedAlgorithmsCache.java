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
package com.ericsson.oss.itpf.security.pkimanager.ra.cache;

import java.util.List;

import com.ericsson.oss.itpf.modeling.annotation.EModel;
import com.ericsson.oss.itpf.modeling.annotation.cache.*;

/**
 * PKIRASupportedAlgorithmsCache is used to store Supported Algorithms for both CMPV2 and SCEP. In Map it Contains Key as Algorithms Type and in The
 * Value as Algorithms OID.
 * 
 * @author xkarlak
 */
@EModel(description = "SupportedAlgorithmsCache is used to store Supported Algorithms", name = "SupportedAlgorithmsCache")
@CacheDefinition(cacheMode = CacheMode.DISTRIBUTED_SYNC, maxEntries = "1000", evictionStrategy = EvictionStrategy.LRU, keyClass = String.class, valueClass = List.class)
public class PKIRASupportedAlgorithmsCache {
}
