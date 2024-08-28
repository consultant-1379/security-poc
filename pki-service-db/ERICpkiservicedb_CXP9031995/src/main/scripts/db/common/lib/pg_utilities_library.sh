##########################################################################
# COPYRIGHT Ericsson 2020
#
# The copyright to the computer program(s) herein is the property of
# Ericsson Inc. The programs may be used and/or copied only with written
# permission from Ericsson Inc. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
##########################################################################
source /ericsson/pki_postgres/db/kaps/lib/postgres01.config
PG_IS_READY=/opt/rh/rh-postgresql94/root/usr/bin/pg_isready

# Ensure script is sourced
[[ "${BASH_SOURCE[0]}" = "$0" ]] && { echo "ERROR: script $0 must be sourced, NOT executed"; exit 1; }

info()
{
    logger -t "${LOG_TAG}" -p user.notice "INFO (${SCRIPT_NAME} ): $1"
}

error()
{
    logger -t "${LOG_TAG}" -p user.err "ERROR (${SCRIPT_NAME} ): $1"
}

#*****************************************************************************#
# This function is used for postgres availabilty
# args :
# 1 : max number of attempts (300 default value)
# 2 : interval between attempts in seconds (10 seconds default value)
#*****************************************************************************#

function pgIsReady() {
  local count=0
  local postgres_ready_max_attempt=${1:-300}
  local interval=${2:-10}

  while [ $count -lt $postgres_ready_max_attempt ] ; do
    out=$($PG_IS_READY -h $HOSTNAME)
    rc=$?
    if [ $rc -eq 0 ] ; then
      info "Postgres is accepting connections"
      break;
    else
      info "Postgres is not yet ready. pg_isready error: $rc"
    fi
    count=$((count+1))
    sleep $interval
  done

  if [ $count -eq $postgres_ready_max_attempt ] ; then
    local totaltime=$(expr $postgres_ready_max_attempt \* $interval)
    error "Error: Postgres is not ready after $totaltime seconds"
    exit 1
  fi
}
