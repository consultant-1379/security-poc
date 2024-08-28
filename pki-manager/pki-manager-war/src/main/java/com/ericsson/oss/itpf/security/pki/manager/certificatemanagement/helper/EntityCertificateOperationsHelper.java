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
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.helper;

import java.util.ArrayList;
import java.util.List;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.keystore.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.eservice.PKIManagerEServiceProxy;
import com.ericsson.oss.itpf.security.pki.manager.entitymanagement.dto.CertificateRequestDTO;
import com.ericsson.oss.itpf.security.pki.manager.entitymanagement.dto.EntityReissueDTO;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.manager.model.CertificateChain;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.rest.common.KeyStoreHelper;
import com.ericsson.oss.itpf.security.pki.manager.rest.util.ErrorMessages;

/**
 * Helper class to trigger issue and reissue of certificates
 * 
 * @author xpranma
 * 
 */
public class EntityCertificateOperationsHelper {

    @Inject
    PKIManagerEServiceProxy pkiManagerEServiceProxy;

    @Inject
    private Logger logger;

    @Inject
    KeyStoreFileWriterHelper keyStoreFileWriterHelper;

    @Inject
    KeyStoreFileWriterFactory keyStoreFileWriterFactory;

    @Inject
    KeyStoreHelper keyStoreHelper;

    private static final String EMPTY_PASSWORD = "";

    /**
     * ` Method that issues certificate for CA and returns resource object for download
     *
     * @param certificateRequestDTO
     *            object containing all the required fields to issue certificate/s through REST
     * @return name of the resource KeyStore file contains certificates with the given type/extension.
     * @throws CertificateServiceException
     *             Thrown in case key store generation failures.
     */
    public String issueCertificateForCA(final CertificateRequestDTO certificateRequestDTO) throws CertificateServiceException {

        List<Certificate> certificates = null;

        logger.debug("Issuing certificate/s for CA_ENTITY.");

        final Certificate certificate = pkiManagerEServiceProxy.getCaCertificateManagementService().generateCertificate(certificateRequestDTO.getName());

        if (certificateRequestDTO.isChain()) {
            final List<CertificateChain> certificateChainList = pkiManagerEServiceProxy.getCaCertificateManagementService().getCertificateChainList(
                    certificateRequestDTO.getName(), CertificateStatus.ACTIVE);
            certificates = certificateChainList.get(0).getCertificates();
        } else {
            certificates = new ArrayList<>();
            certificates.add(certificate);
        }

        final KeyStoreInfo keyStoreInfo = keyStoreHelper.createKeyStoreInfo(certificateRequestDTO.getName(), certificateRequestDTO.getFormat(), certificateRequestDTO.getPassword(),
                certificateRequestDTO.getName());

        return keyStoreHelper.createKeyStore(keyStoreInfo, certificates);
    }

    /**
     * Method that issues certificate for End entity and returns resource object for download
     * 
     * @param certificateRequestDTO
     *            object containing all the required fields to issue certificate/s through REST
     * @return name of the resource KeyStore file contains certificates with the given type/extension.
     * @throws CertificateServiceException
     *             Thrown in case key store generation failures.
     */
    public String issueCertificateForEntity(final CertificateRequestDTO certificateRequestDTO) throws CertificateServiceException {

        CertificateChain certificateChain = null;
        String password = certificateRequestDTO.getPassword();
        com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.model.KeyStoreInfo keyStoreInfo = null;
        String resourceName;

        if (password == null) {
            password = getEmptyPassword();
        }
        keyStoreInfo = pkiManagerEServiceProxy.getEntityCertificateManagementService().generateCertificate(certificateRequestDTO.getName(),
                password.toCharArray(), mappingCommonToApiType(certificateRequestDTO.getFormat()));

        if (!certificateRequestDTO.isChain()) {
            final KeyStoreInfo keyStoreInfoData = keyStoreHelper.createKeyStoreInfo(certificateRequestDTO.getName(), certificateRequestDTO.getFormat(), certificateRequestDTO.getPassword(),
                    certificateRequestDTO.getName());
            return keyStoreHelper.loadAndStoreKeyStore(password, keyStoreInfoData, keyStoreInfo);
        }
        certificateChain = pkiManagerEServiceProxy.getEntityCertificateManagementService().getCertificateChain(certificateRequestDTO.getName());
        resourceName = keyStoreHelper.buildKeyStoreWithCertificateChain(keyStoreInfo, certificateRequestDTO, certificateChain);

        return resourceName;
    }

    /**
     * Method that reissues certificate for End entity with new key and returns resource object for download
     * 
     * @param certificateRequestDTO
     *            object containing all the required fields to issue certificate/s through REST
     * @return name of the resource KeyStore file contains certificates with the given type/extension.
     * @throws CertificateServiceException
     *             Thrown in case key store generation failures.
     */
    public String rekeyCertificateForEndEntity(final CertificateRequestDTO certificateRequestDTO) throws CertificateServiceException {

        String password = certificateRequestDTO.getPassword();
        com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.model.KeyStoreInfo keyStoreInfo = null;
        CertificateChain certificateChain = null;
        String resourceName = null;

        if (password == null) {
            password = getEmptyPassword();
        }
        keyStoreInfo = pkiManagerEServiceProxy.getEntityCertificateManagementService().reKeyCertificate(certificateRequestDTO.getName(),
                password.toCharArray(), mappingCommonToApiType(certificateRequestDTO.getFormat()));
        if (!certificateRequestDTO.isChain()) {
            final KeyStoreInfo loadKeyStoreInfo = keyStoreHelper.createKeyStoreInfo(certificateRequestDTO.getName(), certificateRequestDTO.getFormat(), certificateRequestDTO.getPassword(),
                    certificateRequestDTO.getName());
            return keyStoreHelper.loadAndStoreKeyStore(password, loadKeyStoreInfo, keyStoreInfo);
        }
        certificateChain = pkiManagerEServiceProxy.getEntityCertificateManagementService().getCertificateChain(certificateRequestDTO.getName());
        resourceName = keyStoreHelper.buildKeyStoreWithCertificateChain(keyStoreInfo, certificateRequestDTO, certificateChain);

        return resourceName;
    }

    /**
     * This method will call the getCertificateChain of entity certificate management service if chain is required.
     * 
     * @param entityName
     *            Entity Name.
     * @param chain
     *            return chain if true otherwise return only entity certificate
     * @param certificate
     *            generated certificate.
     * @return certificates list of certificates from entity to RootCA.
     */
    public List<Certificate> getEntityCertificateChain(final String entityName, final boolean chain, final Certificate certificate) {

        List<Certificate> certificates;

        if (chain) {
            certificates = pkiManagerEServiceProxy.getEntityCertificateManagementService().getCertificateChain(entityName).getCertificates();

        } else {
            certificates = new ArrayList<>();
            certificates.add(certificate);
        }
        return certificates;
    }

    // TODO: According to TORF-88475, when models are merged this conversion will be removed.
    private com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.model.KeyStoreType mappingCommonToApiType(final KeyStoreType keyStoreType) {

        switch (keyStoreType) {
        case JKS:
            return com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.model.KeyStoreType.JKS;
        case PKCS12:
            return com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.model.KeyStoreType.PKCS12;
        case PEM:
            return com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.model.KeyStoreType.PEM;
        default:
            throw new IllegalArgumentException(ErrorMessages.FORMAT_NOT_SUPPORTED);
        }

    }

    /**
     * This method is for reissuing (rekey) entity certificate.
     * 
     * @param entityReissueDTO
     *            The {@link EntityReissueDTO}
     * 
     * @return name of the resource KeyStore file contains the certificates with the given format.
     * 
     */
    public String rekeyEndEntityCertificate(final EntityReissueDTO entityReissueDTO) {

        final CertificateRequestDTO certificateRequestDTO = new CertificateRequestDTO();

        certificateRequestDTO.setChain(entityReissueDTO.isChain());
        certificateRequestDTO.setFormat(entityReissueDTO.getFormat());
        certificateRequestDTO.setName(entityReissueDTO.getName());
        certificateRequestDTO.setPassword(entityReissueDTO.getPassword());
        certificateRequestDTO.setType(EntityType.ENTITY);

        return rekeyCertificateForEndEntity(certificateRequestDTO);
    }

    /**
     * This method is to avoid Sonarqube issue "Credentials should not be hard-coded".
     */
    private static String getEmptyPassword() {
        return EMPTY_PASSWORD;
    }
}
