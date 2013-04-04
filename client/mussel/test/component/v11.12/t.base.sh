#!/bin/bash
#
# requires:
#   bash
#

## include files

. ${BASH_SOURCE[0]%/*}/helper_shunit2.sh

## variables

declare namespace=base

## functions

function setUp() {
  state=
  uuid=asdf
}

### index

function test_base_index() {
  local cmd=index
  assertEquals "$(cli_wrapper ${namespace} ${cmd})" \
               "curl -X GET $(base_uri)/${namespace}s.$(suffix)"
}

### show

function test_base_show() {
  local cmd=show

  assertEquals "$(cli_wrapper ${namespace} ${cmd} ${uuid})" \
               "curl -X GET $(base_uri)/${namespace}s/${uuid}.$(suffix)"
}

### destroy

function test_base_destroy() {
  local cmd=destroy

  assertEquals "$(cli_wrapper ${namespace} ${cmd} ${uuid})" \
               "curl -X DELETE $(base_uri)/${namespace}s/${uuid}.$(suffix)"
}

## shunit2

. ${shunit2_file}
