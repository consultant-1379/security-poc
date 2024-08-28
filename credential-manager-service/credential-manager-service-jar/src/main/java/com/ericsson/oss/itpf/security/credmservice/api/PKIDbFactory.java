/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.credmservice.api;

import java.io.IOException;
import java.util.List;

import javax.ejb.Local;

import com.ericsson.oss.itpf.security.credmservice.entities.impl.AppEntityXmlConfiguration;
import com.ericsson.oss.itpf.security.credmservice.exceptions.PkiCategoryMapperException;
import com.ericsson.oss.itpf.security.credmservice.exceptions.PkiEntityMapperException;
import com.ericsson.oss.itpf.security.credmservice.exceptions.PkiProfileMapperException;
import com.ericsson.oss.itpf.security.credmservice.profiles.impl.AppProfileXmlConfiguration;
import com.ericsson.oss.itpf.security.credmservice.util.AppCategoryXmlConfiguration;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.custom.CustomConfigurationAlreadyExistsException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.custom.CustomConfigurationInvalidException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.custom.CustomConfigurationNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.custom.CustomConfigurationServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.CRLExtensionException;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.CRLGenerationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.InvalidCRLGenerationInfoException;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.UnsupportedCRLVersionException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityAlreadyExistsException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.EntityCategoryNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.InvalidEntityCategoryException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.InvalidProfileAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.InvalidProfileException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileAlreadyExistsException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateGenerationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.ExpiredCertificateException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.RevokedCertificateException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.CertificateExtensionException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.InvalidSubjectException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.UnSupportedCertificateVersion;

@Local
public interface PKIDbFactory {

    final static String TRIGGERING_CA_GEN_UPD_FILE = "/ericsson/tor/data/credm/conf/.trigger";

    void PKIDbConf(List<AppProfileXmlConfiguration> xmlProfiles, List<AppEntityXmlConfiguration> xmlEntities)
            throws PkiProfileMapperException, PkiEntityMapperException, ProfileServiceException, EntityServiceException, CANotFoundException,
            ProfileNotFoundException, EntityNotFoundException, CertificateExtensionException, InvalidSubjectException, MissingMandatoryFieldException,
            UnSupportedCertificateVersion, AlgorithmNotFoundException, EntityCategoryNotFoundException, InvalidCAException,
            InvalidEntityCategoryException, InvalidProfileAttributeException, ProfileAlreadyExistsException, EntityAlreadyExistsException,
            InvalidEntityAttributeException, InvalidProfileException, UnsupportedCRLVersionException, CRLExtensionException,
            InvalidCRLGenerationInfoException, CertificateGenerationException, CertificateServiceException, IOException, ExpiredCertificateException,
            RevokedCertificateException, InvalidEntityException, CRLGenerationException;

    /**
     * @throws Exception
     *
     */
    void importExtCaCertificate() throws Exception;

    /**
     *
     */
    void pkiCategoryDbConf(AppCategoryXmlConfiguration xmlCategories) throws PkiCategoryMapperException;

    /**
     *
     */
    void setCAGenUpgrade(final boolean trigger);

    /**
     *
     */
    boolean getCAGenUpgrade();

    /**
     *
     */
    void cvnInit() throws CustomConfigurationNotFoundException, CustomConfigurationInvalidException, CustomConfigurationServiceException;

    /**
    *
    */

    void updateCvnOnPki() throws CustomConfigurationInvalidException, CustomConfigurationServiceException, CustomConfigurationAlreadyExistsException;

    /**
    *
    */

    boolean readAndCheckCvn() throws CustomConfigurationNotFoundException, CustomConfigurationInvalidException, CustomConfigurationServiceException;

}
