ARG ERIC_ENM_SLES_EAP7_IMAGE_NAME=eric-enm-sles-eap7
ARG ERIC_ENM_SLES_EAP7_IMAGE_REPO=armdocker.rnd.ericsson.se/proj-enm
ARG ERIC_ENM_SLES_EAP7_IMAGE_TAG=1.29.0-8

FROM ${ERIC_ENM_SLES_EAP7_IMAGE_REPO}/${ERIC_ENM_SLES_EAP7_IMAGE_NAME}:${ERIC_ENM_SLES_EAP7_IMAGE_TAG}

ARG BUILD_DATE=unspecified
ARG IMAGE_BUILD_VERSION=unspecified
ARG GIT_COMMIT=unspecified
ARG ISO_VERSION=unspecified
ARG RSTATE=unspecified
ARG NEXUS_BASE_POC_URL=https://arm1s11-eiffel004.eiffel.gic.ericsson.se:8443/nexus/service/local/artifact/maven/redirect?r=snapshots&g=com.ericsson.oss.itpf.poc.security

LABEL \
com.ericsson.product-number="CXC 174 1995" \
com.ericsson.product-revision=$RSTATE \
enm_iso_version=$ISO_VERSION \
org.label-schema.name="ENM SPS Service Group" \
org.label-schema.build-date=$BUILD_DATE \
org.label-schema.vcs-ref=$GIT_COMMIT \
org.label-schema.vendor="Ericsson" \
org.label-schema.version=$IMAGE_BUILD_VERSION \
org.label-schema.schema-version="1.0.0-rc1"

RUN mkdir -p /ericsson/enm/sps_cliconf \
    mkdir -p /ericsson/tor/data/shm

RUN zypper install -y \
    ERICpostgresqljdbc_CXP9031176 \
    ERICserviceframework4_CXP9037454 \
    ERICserviceframeworkmodule4_CXP9037453 \
    ERICmodelserviceapi_CXP9030594 \
    ERICmodelservice_CXP9030595 \
    ERICpib2_CXP9037459 \
    sles_base_os_repo:postgresql13 \
    # ERICpkiservicedb_CXP9031995 \
    # ERICpkimanagerapi_CXP9031871 \
    # ERICpkicoreapi_CXP9031872 \
    # ERICpkicore_CXP9031876 \
    # ERICpkimanager_CXP9031873 \
    # ERICpkiwebcli_CXP9031880 \
    # ERICcredentialmanagerservice_CXP9031868 \
    # ERICcredentialmanagerwebclihandler_CXP9031827 \ # not used
    # ERICkeyaccessproviderservice_CXP9032385 \
    ERICvaultloginmodule_CXP9036201 \
    wget \
    ERICpostgresutils_CXP9038493 && \
    zypper download ERICenmsgsps_CXP9031956 && \
    rpm -ivh /var/cache/zypp/packages/enm_iso_repo/ERICenmsgsps_CXP9031956*.rpm --nodeps --noscripts && \
    zypper clean -a && \
    rm -f /ericsson/3pp/jboss/bin/pre-start/copy_cache_replication_config_xml_files.sh && \
    rm -f /ericsson/3pp/jboss/bin/pre-start/oomKillerTuning.sh

RUN wget -q -O /tmp/ERICpkiservicedb_CXP9031995.rpm "${NEXUS_BASE_POC_URL}&a=ERICpkiservicedb_CXP9031995&v=1.0.1-SNAPSHOT&p=rpm" && \
    wget -q -O /tmp/ERICpkimanagerapi_CXP9031871.rpm "${NEXUS_BASE_POC_URL}&a=ERICpkimanagerapi_CXP9031871&v=1.0.1-SNAPSHOT&p=rpm" && \
    wget -q -O /tmp/ERICpkicoreapi_CXP9031872.rpm "${NEXUS_BASE_POC_URL}&a=ERICpkicoreapi_CXP9031872&v=1.0.1-SNAPSHOT&p=rpm" && \
    wget -q -O /tmp/ERICpkicore_CXP9031876.rpm "${NEXUS_BASE_POC_URL}&a=ERICpkicore_CXP9031876&v=1.0.1-SNAPSHOT&p=rpm" && \
    wget -q -O /tmp/ERICpkimanager_CXP9031873.rpm "${NEXUS_BASE_POC_URL}&a=ERICpkimanager_CXP9031873&v=1.0.4-SNAPSHOT&p=rpm" && \
    wget -q -O /tmp/ERICpkiwebcli_CXP9031880.rpm "${NEXUS_BASE_POC_URL}&a=ERICpkiwebcli_CXP9031880&v=1.0.1-SNAPSHOT&p=rpm" && \
    wget -q -O /tmp/ERICcredentialmanagerservice_CXP9031868.rpm "${NEXUS_BASE_POC_URL}&a=ERICcredentialmanagerservice_CXP9031868&v=1.0.5-SNAPSHOT&p=rpm" && \
    wget -q -O /tmp/ERICkeyaccessproviderservice_CXP9032385.rpm "${NEXUS_BASE_POC_URL}&a=ERICkeyaccessproviderservice_CXP9032385&v=1.0.1-SNAPSHOT&p=rpm" && \
    wget -q -O /tmp/ERICscripteng_CXP9030314.rpm "${NEXUS_BASE_POC_URL}&a=ERICscripteng_CXP9030314&v=1.0.1-SNAPSHOT&p=rpm"

# only if you work with your local rpm
# COPY ./SNAPSHOTS/* /tmp/

RUN rpm -ivh /tmp/ERICpkiservicedb_CXP9031995.rpm && \
    rpm -ivh /tmp/ERICpkimanagerapi_CXP9031871.rpm && \
    rpm -ivh /tmp/ERICpkicoreapi_CXP9031872.rpm && \
    rpm -ivh /tmp/ERICpkicore_CXP9031876.rpm && \
    rpm -ivh /tmp/ERICpkimanager_CXP9031873.rpm && \
    rpm -ivh /tmp/ERICpkiwebcli_CXP9031880.rpm && \
    rpm -ivh /tmp/ERICcredentialmanagerservice_CXP9031868.rpm && \
    rpm -ivh /tmp/ERICkeyaccessproviderservice_CXP9032385.rpm && \
    rpm -ivh /tmp/ERICscripteng_CXP9030314.rpm

COPY eric-enmsg-sps-service-init/image_content/sps_config.sh  /var/tmp/
COPY eric-enmsg-sps-service-init/image_content/spsCertificateCheck.sh /var/tmp/
COPY image_content/accessControlImpl.sh  /var/tmp/
RUN mkdir -p /com/ericsson/oss/itpf/sdk/security/accesscontrol/classic/
COPY image_content/EAccessControlImpl.class /com/ericsson/oss/itpf/sdk/security/accesscontrol/classic/

ENV ENM_JBOSS_SDK_CLUSTER_ID="sps" \
    ENM_JBOSS_BIND_ADDRESS="0.0.0.0" \
    CLOUD_DEPLOYMENT=TRUE \
    JBOSS_CONF="/ericsson/3pp/jboss/app-server.conf"

RUN sed -i "9 a bash /var/tmp/sps_config.sh" /ericsson/3pp/jboss/entry_point.sh
RUN chmod a+x /var/tmp/*.sh
RUN chmod a+x /usr/lib/ocf/resource.d/deploy_failure_detection.sh

RUN mkdir -p /opt/rh/postgresql
RUN ln -s /usr/lib/postgresql13/bin /opt/rh/postgresql/bin
RUN mkdir -p /opt/rh/rh-postgresql94/root/usr/
RUN ln -s /usr/lib/postgresql13/bin /opt/rh/rh-postgresql94/root/usr/bin

RUN sh /var/tmp/accessControlImpl.sh

EXPOSE 1636 4320 4447 7999 8009 8445 8080 8085 9990 9999 12987 41610 51088 54200 55500 55501 56400 56401 56402 56406 56407 56408 56412 56413 56414 56418 56419 56420 59309
