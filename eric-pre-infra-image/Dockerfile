ARG ERIC_ENM_SLES_BASE_IMAGE_NAME=eric-enm-sles-base
ARG ERIC_ENM_SLES_BASE_IMAGE_REPO=armdocker.rnd.ericsson.se/proj-enm
ARG ERIC_ENM_SLES_BASE_IMAGE_TAG=1.30.0-3

FROM ${ERIC_ENM_SLES_BASE_IMAGE_REPO}/${ERIC_ENM_SLES_BASE_IMAGE_NAME}:${ERIC_ENM_SLES_BASE_IMAGE_TAG}

ARG BUILD_DATE=unspecified
ARG GIT_COMMIT=unspecified
ARG IMAGE_BUILD_VERSION=unspecified
ARG ISO_VERSION=unspecified
ARG RSTATE=unspecified
LABEL com.ericsson.product-number="CXC Placeholder" \
      com.ericsson.product-revision=$RSTATE \
      enm_iso_version=$ISO_VERSION \
      org.label-schema.build-date=$BUILD_DATE \
      org.label-schema.name="ENM pre infra" \
      org.label-schema.schema-version="1.0.0-rc1" \
      org.label-schema.vcs-ref=$GIT_COMMIT \
      org.label-schema.vendor="Ericsson" \
      org.label-schema.version=$IMAGE_BUILD_VERSION

COPY image_content/* /var/tmp/

