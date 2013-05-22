#!/bin/bash
#
# requires:
#  bash
#

## include files

. ${BASH_SOURCE[0]%/*}/helper_shunit2.sh

## variables

declare instance_ipaddr=
declare instance_uuids_path=$(generate_cache_file_path instance_uuids)

function needs_vif() { true; }
function needs_secg() { true; }
function ping() { :; }
function nc() { :; }

ssh_user=${ssh_user:-root}
image_id=${image_id_lbnode:-wmi-lbnode}
vifs_eth0_network_id=${vifs_eth0_network_id:-nw-demo1}

api_client_addr=$(for i in $(ip route get ${DCMGR_HOST} | head -1); do echo ${i}; done | tail -1)
global_addr=${global_addr:-211.19.101.215}

target_instance_num=${target_instance_num:-4}

cat <<-EOS > ${rule_path}
EOS
empty_rule=${rule_path}
rule=${rule_path}

cat <<-EOS > ${rule_path}
icmp:-1,-1,ip4:${global_addr}/32
tcp:22,22,ip4:${global_addr}/32
EOS
globalip_rule=${rule_path}

security_group_default=
security_group_aaa=
security_group_bbb=

empty_security_group_uuid=
ssh_and_icmp_security_group_uuid=

## functions

function render_vif_table() {
  cat <<-EOS
	{"eth0":{"index":"0","network":"${vifs_eth0_network_id}","security_groups":["${empty_security_group_uuid}","${lb_security_group_uuid}","${security_group_default}"]}}
	EOS
}

function show_host_node(){
  run_cmd instance show $1 | grep :host_node | awk '{print $2}'
}

function before_create_instance() {
  # don't clear ssh_key_pair_uuid= to apply same keypair to instances
  instance_uuid=
}

function oneTimeSetUp() {
  security_group_default=$(display_name="sg-default" run_cmd security_group create | hash_value id)
  security_group_additional=$(display_name="sg-additional" run_cmd security_group create | hash_value id)
  sg_A=$(display_name="sg-A" run_cmd security_group create | hash_value id)
  rule=${globalip_rule}
  sg_global_a=$(display_name="sg-GlobalA" run_cmd security_group create | hash_value id)
  rule=${empty_rule}
  sg_B=$(display_name="sg-B" run_cmd security_group create | hash_value id)
  sg_global_b=$(display_name="sg-GlobalB" run_cmd security_group create | hash_value id)
  sg_C=$(display_name="sg-C" run_cmd security_group create | hash_value id)
  sg_global_c=$(display_name="sg-GlobalC" run_cmd security_group create | hash_value id)
  sg_D=$(display_name="sg-D" run_cmd security_group create | hash_value id)
  rule=${globalip_rule}
  sg_global_d=$(display_name="sg-GlobalD" run_cmd security_group create | hash_value id)

  cat <<-EOS > ${rule_path}
icmp:-1,-1,${sg_B}
icmp:-1,-1,${sg_C}
tcp:22,22,${sg_B}
tcp:22,22,${sg_C}
tcp:8001,8001,${sg_B}
tcp:8002,8002,${sg_C}
EOS
  rule=${rule_path}
  run_cmd security_group update ${sg_A}

  cat <<-EOS > ${rule_path}
icmp:-1,-1,${sg_A}
icmp:-1,-1,${sg_D}
tcp:22,22,${sg_A}
tcp:22,22,${sg_D}
tcp:8011,8011,${sg_A}
tcp:8012,8012,${sg_D}
EOS
  rule=${rule_path}
  run_cmd security_group update ${sg_B}

  # instanceA
  empty_security_group_uuid=${sg_A}
  lb_security_group_uuid=${sg_global_a}
  host_group=gsva create_instance
  echo ${instance_uuid} >> ${instance_uuids_path}
  echo "$(cached_instance_param ${instance_uuid})"

  # instanceB
  empty_security_group_uuid=${sg_B}
  lb_security_group_uuid=${sg_global_b}
  host_group=gsvb create_instance
  echo ${instance_uuid} >> ${instance_uuids_path}
  echo "$(cached_instance_param ${instance_uuid})"

  # instanceC
  empty_security_group_uuid=${sg_C}
  lb_security_group_uuid=${sg_global_c}
  host_group=gsva create_instance
  echo ${instance_uuid} >> ${instance_uuids_path}
  echo "$(cached_instance_param ${instance_uuid})"

  # instanceD
  empty_security_group_uuid=${sg_D}
  lb_security_group_uuid=${sg_global_d}
  host_group=gsvb create_instance
  echo ${instance_uuid} >> ${instance_uuids_path}
  echo "$(cached_instance_param ${instance_uuid})"

  # wait
  for instance_uuid in $(cat ${instance_uuids_path}); do
    local instance_ipaddr="$(cached_instance_param ${instance_uuid} | hash_value address)"
    wait_for_network_to_be_ready ${instance_ipaddr}
    wait_for_sshd_to_be_ready    ${instance_ipaddr}
  done
}

function oneTimeTearDown() {
  for instance_uuid in $(cat ${instance_uuids_path}); do
    ssh_key_pair_uuid="$(cached_instance_param ${instance_uuid}   | egrep ' ssh-' | awk '{print $2}')"
    security_group_uuid="$(cached_instance_param ${instance_uuid} | egrep ' sg-'  | awk '{print $2}')"
    destroy_instance
  done

  rm -f ${instance_uuids_path}

  run_cmd security_group index | grep ':id:' | awk '{print $3}' | while read security_group_id; do
    echo ${security_group_id}
    run_cmd security_group destroy ${security_group_id}
  done

  run_cmd ssh_key_pair index | grep ':id:' | awk '{print $3}' | while read ssh_key_pair_id; do
    echo ${ssh_key_pair_id}
    run_cmd ssh_key_pair destroy ${ssh_key_pair_id}
  done
}

### step

function test_complex_security_group() {

  local instance_uuids=()
  for instance_uuid in $(cat ${instance_uuids_path}); do
    instance_uuids+=($instance_uuid)
  done

  # i-A
  local instance_a=${instance_uuids[0]}
  local vif_a="$(cached_instance_param ${instance_a} | hash_value vif_id)"
  local ipaddr_a="$(cached_instance_param ${instance_a} | hash_value address)"

  # i-B
  local instance_b=${instance_uuids[1]}
  local vif_b="$(cached_instance_param ${instance_b} | hash_value vif_id)"
  local ipaddr_b="$(cached_instance_param ${instance_b} | hash_value address)"

  # i-C
  local instance_c=${instance_uuids[2]}
  local vif_c="$(cached_instance_param ${instance_c} | hash_value vif_id)"
  local ipaddr_c="$(cached_instance_param ${instance_c} | hash_value address)"

  # i-D
  local instance_d=${instance_uuids[3]}
  local vif_d="$(cached_instance_param ${instance_d} | hash_value vif_id)"
  local ipaddr_d="$(cached_instance_param ${instance_d} | hash_value address)"

  echo ====================
  echo i-A
  echo $instance_a
  echo $vif_a
  echo $ipaddr_a
  show_host_node ${instance_a}
  echo ====================
  echo i-B
  echo $instance_b
  echo $vif_b
  echo $ipaddr_b
  show_host_node ${instance_b}
  echo ====================
  echo i-C
  echo $instance_c
  echo $vif_c
  echo $ipaddr_c
  show_host_node ${instance_c}
  echo ====================
  echo i-D
  echo $instance_d
  echo $vif_d
  echo $ipaddr_d
  show_host_node ${instance_d}
  echo ====================
    echo sg-default: ${security_group_default}
    echo sg-additional: ${security_group_additional}
    echo sg-A: ${sg_A}, sg-GlobalA: ${sg_global_a}
    echo sg-B: ${sg_B}, sg-GlobalB: ${sg_global_b}
    echo sg-C: ${sg_C}, sg-GlobalC: ${sg_global_c}
    echo sg-D: ${sg_D}, sg-GlobalD: ${sg_global_d}
  echo ====================
    echo global_addr: ${global_addr}
  echo ====================
  echo
  echo setup finished
  echo press ctrl-D to start tests
  cat

  echo "##### scenario: i"
  run_cmd instance poweroff $instance_a
  echo press ctrl-D to start tests;cat
  echo "##### scenario: ii"
  run_cmd instance poweron $instance_a
  echo press ctrl-D to start tests;cat
  echo "##### scenario: iii"
  run_cmd instance poweroff $instance_d
  echo press ctrl-D to start tests;cat
  echo "##### scenario: iv"
  run_cmd instance poweron $instance_d
  echo press ctrl-D to start tests;cat

  echo "##### scenario: v"
  security_group_id=$security_group_additional
  run_cmd network_vif add_security_group $vif_a
  echo press ctrl-D to start tests;cat
  echo "##### scenario: vi"
  security_group_id=$security_group_additional
  run_cmd network_vif add_security_group $vif_b
  echo press ctrl-D to start tests;cat
  echo "##### scenario: vii"
  security_group_id=$security_group_additional
  run_cmd network_vif remove_security_group $vif_b
  echo press ctrl-D to start tests;cat
  echo "##### scenario: viii"
  security_group_id=$security_group_additional
  run_cmd network_vif add_security_group $vif_b
  echo press ctrl-D to start tests;cat
  echo "##### scenario: ix"
  security_group_id=$security_group_additional
  run_cmd network_vif add_security_group $vif_c
  echo press ctrl-D to start tests;cat

  echo "##### scenario: x"
  cat <<-EOS > ${rule_path}
icmp:-1,-1,${sg_C}
icmp:-1,-1,ip4:${global_addr}/32
tcp:22,22,${sg_C}
tcp:22,22,ip4:${global_addr}/32
tcp:8011,8021,${sg_C}
tcp:8012,8022,ip4:${global_addr}/32
EOS
  rule=${rule_path}
  run_cmd security_group update ${security_group_additional}
  echo press ctrl-D to start tests;cat
  echo "##### scenario: xi"
  cat <<-EOS > ${rule_path}
EOS
  rule=${rule_path}
  run_cmd security_group update ${security_group_additional}
  echo press ctrl-D to start tests;cat

  echo "##### scenario: xii"
  security_group_id=$security_group_additional
  run_cmd network_vif remove_security_group $vif_a
  echo press ctrl-D to start tests;cat
  echo "##### scenario: xiii"
  security_group_id=$security_group_additional
  run_cmd network_vif remove_security_group $vif_b
  echo press ctrl-D to start tests;cat
  echo "##### scenario: xiv"
  security_group_id=$security_group_additional
  run_cmd network_vif remove_security_group $vif_c
  echo press ctrl-D to start tests;cat

  echo "##### scenario: xv"
  security_group_id=$security_group_additional
  run_cmd network_vif add_security_group $vif_a
  run_cmd network_vif add_security_group $vif_b
  run_cmd network_vif add_security_group $vif_c
  echo press ctrl-D to start tests;cat
  echo "##### scenario: xvi"
  security_group_id=$security_group_default
  run_cmd network_vif remove_security_group $vif_a
  run_cmd network_vif remove_security_group $vif_b
  run_cmd network_vif remove_security_group $vif_c
  echo press ctrl-D to start tests;cat
  echo "##### scenario: xvii"
  security_group_id=$security_group_default
  run_cmd network_vif add_security_group $vif_c
  echo "##### scenario: xviii"
  security_group_id=$security_group_default
  run_cmd network_vif remove_security_group $vif_c
  run_cmd network_vif remove_security_group $vif_d
  run_cmd network_vif add_security_group $vif_a
  run_cmd network_vif add_security_group $vif_b
  echo press ctrl-D to start tests;cat

}

## shunit2

. ${shunit2_file}
