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
package com.ericsson.oss.itpf.security.pki.core.crlmanagement.builder;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.inject.Inject;
import javax.persistence.Query;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdkutils.rest.json.JsonUtil;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.crl.entryextension.CrlEntryExtensions;
import com.ericsson.oss.itpf.security.pki.common.model.crl.revocation.RevocationReason;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.core.crlmanagement.crlgenerator.RevokedCertificatesInfo;
import com.ericsson.oss.itpf.security.pki.core.exception.revocation.RevocationServiceException;

/**
 * This class will fetch the list of all the revoked certificates and their revocation reasons for a given issuer certificate
 * 
 * @author xananer
 * 
 */
public class RevokedCertificatesInfoBuilder {

    @Inject
    Logger logger;

    @Inject
    PersistenceManager persistenceManager;

    private final static String revokedCertificatesNativeQueryString = "SELECT c.serial_number, c.revoked_time, r.crl_entry_extensions FROM revocation_request r JOIN revocation_request_certificate rc ON r.id = rc.revocation_id JOIN certificate c ON rc.certificate_id = c.id WHERE c.status_id = 3 AND c.not_after > localtimestamp AND c.issuer_certificate_id = ";

    /**
     * This method will build the list of certificates revoked for a given issuerCertificate
     * 
     * @param issuerCertificate
     *            is the issuerCertificate for which the revoked certificates have to be fetched
     * @return list of revoked certificates for a given issuer certificate
     * @throws RevocationServiceException
     *             thrown to indicate any internal database errors in case of Revocation.
     */
    public List<RevokedCertificatesInfo> buildRevokedCertificateInfo(final Certificate issuerCertificate) throws RevocationServiceException {

        logger.info("This is generateCRL method of CrlV2Generator class");
        final List<RevokedCertificatesInfo> revokedCertificateInfoList = new ArrayList<>();

        final Query revokedCertificatesNativeQuery = persistenceManager.getEntityManager().createNativeQuery(
                revokedCertificatesNativeQueryString + issuerCertificate.getId());

        final List<Object[]> revokedCertificates =  (List<Object[]>) revokedCertificatesNativeQuery.getResultList();

        for (Object[] revokedCertificate : revokedCertificates) {
                final RevokedCertificatesInfo revokedCertificateInfo = getRevokedCertificateInfo(revokedCertificate);
                revokedCertificateInfoList.add(revokedCertificateInfo);
        }
        return revokedCertificateInfoList;
    }

    /**
     * This method will fetch the reason for each of the revoked certificate
     * 
     * @param revokedCertificate
     *            is the certificate for which the revocation reason has to be fetched
     * @return
     */
    private RevokedCertificatesInfo getRevokedCertificateInfo(final Object[] revokedCertificate) throws RevocationServiceException {

        final RevokedCertificatesInfo revokedCertificateInfo = new RevokedCertificatesInfo();

        revokedCertificateInfo.setSerialNumber((String) revokedCertificate[0]);

        final CrlEntryExtensions crlEntryExtensions = JsonUtil.getObjectFromJson(CrlEntryExtensions.class, (String) revokedCertificate[2]);

        if (crlEntryExtensions.getReasonCode().getRevocationReason() != null) {
            revokedCertificateInfo.setRevocationReason(crlEntryExtensions.getReasonCode().getRevocationReason().getRevocationReason());
        } else {
            revokedCertificateInfo.setRevocationReason(RevocationReason.UNSPECIFIED.getRevocationReason());
        }

        revokedCertificateInfo.setInvalidityDate(crlEntryExtensions.getInvalidityDate().getInvalidityDate());
        revokedCertificateInfo.setRevocationDate((Date) revokedCertificate[1]);

        return revokedCertificateInfo;
    }
}
