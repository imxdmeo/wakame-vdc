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
global_addr="211.19.101.215"

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
function show_host_node(){
  run_cmd instance show $1 | grep :host_node | awk '{print $2}'
}

function render_vif_table() {
  cat <<-EOS
        {"eth0":{"index":"0","network":"${vifs_eth0_network_id}","security_groups":["${security_group_uuid}"]}}
EOS
}

function before_create_instance() {
  # don't clear ssh_key_pair_uuid= to apply same keypair to instances
  instance_uuid=
}

function oneTimeSetUp() {
  api_client_addr=$(for i in $(ip route get 8.8.8.8 | head -1); do echo ${i}; done | tail -1)
  cat <<-EOS > ${rule_path}
icmp:-1,-1,ip4:${api_client_addr}/32
tcp:22,22,ip4:${api_client_addr}/32
EOS
  rule=${rule_path}
  security_group_uuid=$(display_name="from_client" run_cmd security_group create | hash_value id)

  rule=${empty_rule}
  sg_B=$(display_name="sg-B" run_cmd security_group create | hash_value id)

  cat <<-EOS > ${rule_path}
icmp:-1,-1,${sg_B}
tcp:80,80,${sg_B}
EOS
  rule=${rule_path}
  sg_A=$(display_name="sg-A" run_cmd security_group create | hash_value id)

  # instanceA
  create_instance
  echo ${instance_uuid} >> ${instance_uuids_path}
  echo "$(cached_instance_param ${instance_uuid})"

  # instanceB
  create_instance
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

  cat <<-EOS > ${rule_path}
#
EOS
  rule=${rule_path}
  run_cmd security_group index | grep ':id:' | awk '{print $3}' | while read security_group_id; do
    echo ${security_group_id}
    run_cmd security_group update ${security_group_id}
  done
  run_cmd security_group index | grep ':id:' | awk '{print $3}' | while read security_group_id; do
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
    echo sg-A: ${sg_A}
    echo sg-B: ${sg_B}
  echo

  echo setup finished
  echo press ctrl-D to start tests
  cat

  echo "##### scenario: 4. ins-A:Hostにsg-Aを割り当てる。"
  security_group_id=$sg_A
  run_cmd network_vif add_security_group $vif_a

  # ssh ${ssh_user}@${ipaddr_a} -i ${ssh_key_pair_path} "ping -c 1 -W 3 ${ipaddr_b}"
  # assertEquals "i-A -> i-B" $? 0
  # ssh ${ssh_user}@${ipaddr_b} -i ${ssh_key_pair_path} "ping -c 1 -W 3 ${ipaddr_a}"
  # assertEquals "i-B -> i-A" $? 0

  echo press ctrl-D to continue tests;cat
  echo "##### scenario: 5. ins-B:Hostにsg-Bを割り当てる。"
  security_group_id=$sg_B
  run_cmd network_vif add_security_group $vif_b

  # ssh ${ssh_user}@${ipaddr_a} -i ${ssh_key_pair_path} "ping -c 1 -W 3 ${ipaddr_b}"
  # assertEquals "i-A -> i-B" $? 0
  # ssh ${ssh_user}@${ipaddr_b} -i ${ssh_key_pair_path} "ping -c 1 -W 3 ${ipaddr_a}"
  # assertEquals "i-B -> i-A" $? 0
  echo press ctrl-D to continue tests;cat

}

## shunit2

. ${shunit2_file}
