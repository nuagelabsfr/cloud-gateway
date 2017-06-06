#!/bin/bash

SCRIPTS_DIR=`dirname $0`
BUILD_DIR=${SCRIPTS_DIR}/../../build/
BUILD_COVERAGE_DIR=${SCRIPTS_DIR}/../../build-coverage/
SRC_DIR=${SCRIPTS_DIR}/../../src

VALGRIND_BIN=/usr/bin/valgrind

if [ $# -eq 1 ]; then
    VALGRIND_LEAK_CHECK=$1
else
    VALGRIND_LEAK_CHECK="full"
fi

VALGRIND_SUPP_FILE=${SCRIPTS_DIR}/valgrind.supp
VALGRIND_OPT="--leak-check=${VALGRIND_LEAK_CHECK} --show-reachable=yes -q --track-fds=yes --num-callers=50 --suppressions=${VALGRIND_SUPP_FILE}" #--gen-suppressions=all"

if [ -n "${NOVG}" ]; then
    VALGRIND=""
else
    VALGRIND="${VALGRIND_BIN} ${VALGRIND_OPT}"
fi

DEBUG_LIBS_DIR=${SCRIPTS_DIR}/../../debug-libs
export LD_LIBRARY_PATH="${LD_LIBRARY_PATH}:${DEBUG_LIBS_DIR}"
