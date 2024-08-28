package com.ericsson.oss.itpf.security.credmservice.ejb.startup;
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
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.sdk.resources.Resource;
import com.ericsson.oss.itpf.sdk.resources.Resources;

// Transactions are required for JCA implementations to work properly
@Stateless
public class JcaFileResourceBean {

    private final Logger log = LoggerFactory.getLogger(getClass());

    private Resource resource;

    public void init(final String absoluteUri) {
        this.resource = Resources.getFileSystemResource(absoluteUri);
    }

    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    public int write(final byte[] content, final boolean append) {
        return resource.write(content, append);
    }

    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    public boolean delete() {
        return resource.delete();
    }

    public long getLastModificationTimestamp() {
        return resource.getLastModificationTimestamp();
    }

    public boolean supportsWriteOperations() {
        return resource.supportsWriteOperations();
    }

    public boolean exists() {
        return resource.exists();
    }


}
