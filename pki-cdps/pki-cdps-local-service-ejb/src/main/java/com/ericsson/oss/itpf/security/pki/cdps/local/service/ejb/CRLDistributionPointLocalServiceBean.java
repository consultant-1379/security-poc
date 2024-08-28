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
package com.ericsson.oss.itpf.security.pki.cdps.local.service.ejb;

import java.util.List;

import javax.ejb.Stateless;
import javax.inject.Inject;

import com.ericsson.oss.itpf.security.pki.cdps.api.exception.CRLDistributionPointServiceException;
import com.ericsson.oss.itpf.security.pki.cdps.cdt.CACertificateInfo;
import com.ericsson.oss.itpf.security.pki.cdps.cdt.CRLInfo;
import com.ericsson.oss.itpf.security.pki.cdps.common.EventNotificationPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.cdps.local.service.api.CRLDistributionPointLocalService;

/**
 * This class Publish CRL's using list of CRLInfo's and Unpublish CRL's using list of CACertificateInfo's to CDPS database using EventNotificationPersistenceHandler class.
 * 
 * @author xchowja
 *
 */
@Stateless
public class CRLDistributionPointLocalServiceBean implements CRLDistributionPointLocalService {

    @Inject
    EventNotificationPersistenceHandler eventNotificationPersistenceHandler;

    @Override
    public void publishCRL(final List<CRLInfo> crlInfoList) throws CRLDistributionPointServiceException {
        eventNotificationPersistenceHandler.publishCRL(crlInfoList);
    }

    @Override
    public void unPublishCRL(final List<CACertificateInfo> caCertificateInfos) throws CRLDistributionPointServiceException {
        eventNotificationPersistenceHandler.unPublishCRL(caCertificateInfos);
    }
}