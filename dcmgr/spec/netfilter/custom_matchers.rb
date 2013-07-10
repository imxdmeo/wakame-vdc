# -*- coding: utf-8 -*-

module ChainMethods
  def succeed_with(msg)
    @fail_should_not = msg
    true
  end

  def fail_with(msg)
    @fail_should = msg
    false
  end

  def expect_chains(bin, chains)
    actual_chains = @nfa.all_chain_names(bin)
    if (actual_chains & chains).sort == chains.sort
      succeed_with "There were chains applied that we expected not to.\n
      chains: [#{actual_chains.join(", ")}]"
    else
      fail_with "The chains we expected weren't applied.\n
      expected: [#{chains.join(", ")}]\n
      got: [#{actual_chains.join(", ")}]"
    end
  end

  def expect_rules(bin, chain, rules)
    actual = @nfa.get_chain(bin, chain).rules.sort
    expected = rules.sort

    if actual == expected
      succeed_with "Chain '#{chain}' had the rules we expected it not to have.\n
      jumps: [#{actual.join(", ")}]"
    else
      fail_with "Chain '#{chain}' didn't have the rules we expected.\n
      expected: [#{expected.join(", ")}]\n
      got: [#{actual.join(", ")}]"
    end
  end

  def expect_jumps(bin, chain, targets)
    actual = @nfa.get_chain(bin, chain).jumps.sort
    expected = targets.sort

    if actual == expected
      succeed_with "Chain '#{chain}' had jumps we expected it not to have.\n
      jumps: [#{actual.join(", ")}]"
    else
      fail_with "Chain '#{chain}' didn't have the jumps we expected.\n
      expected: [#{expected.join(", ")}]\n
      got: [#{actual.join(", ")}]"
    end
  end
end

RSpec::Matchers.define :have_applied_vnic do |vnic|
  include ChainMethods

  def l2_chains_for_vnic
    [
      "vdc_#{@vnic_id}_d",
      "vdc_#{@vnic_id}_d_isolation",
      "vdc_#{@vnic_id}_d_reffers",
      "vdc_#{@vnic_id}_d_standard"
    ]
  end

  def l3_chains_for_vnic
    [
      "vdc_#{@vnic_id}_d",
      "vdc_#{@vnic_id}_d_isolation",
      "vdc_#{@vnic_id}_d_reffees",
      "vdc_#{@vnic_id}_d_security",
      "vdc_#{@vnic_id}_d_standard"
    ]
  end

  def group_chains(suffix)
    @groups.map {|g| "vdc_#{g.canonical_uuid}_#{suffix}" }
  end

  chain :with_secgs do |secg_array|
    @groups = secg_array
  end

  match do |nfa|
    @nfa = nfa
    @vnic_id = vnic.canonical_uuid

    expect_chains("ebtables", l2_chains_for_vnic) &&
    expect_chains("iptables", l3_chains_for_vnic) &&
    ( @groups.nil? || (
      expect_jumps("ebtables", "vdc_#{@vnic_id}_d_isolation", group_chains("isolation")) &&
      expect_jumps("ebtables", "vdc_#{@vnic_id}_d_reffers", group_chains("reffers")) &&
      expect_jumps("iptables", "vdc_#{@vnic_id}_d_isolation", group_chains("isolation")) &&
      expect_jumps("iptables", "vdc_#{@vnic_id}_d_security", group_chains("rules")) &&
      expect_jumps("iptables", "vdc_#{@vnic_id}_d_reffees", group_chains("reffees"))
    ))
  end

  failure_message_for_should {|nfa| @fail_should}
  failure_message_for_should_not {|nfa| @fail_should_not}
end

RSpec::Matchers.define :have_applied_secg do |secg|
  include ChainMethods

  def l2_chains_for_secg(secg_id)
    ["vdc_#{secg_id}_reffers", "vdc_#{secg_id}_isolation"]
  end

  def l3_chains_for_secg(secg_id)
    [
      "vdc_#{secg_id}_rules",
      "vdc_#{secg_id}_reffees",
      "vdc_#{secg_id}_isolation"
    ]
  end

  def l2_iso_rules
    @vnics.map {|v| "--protocol arp --arp-opcode Request --arp-ip-src #{v.direct_ip_lease.first.ipv4} -j ACCEPT" }
  end

  def l3_iso_rules
    @vnics.map {|v| "-s #{v.direct_ip_lease.first.ipv4} -j ACCEPT"}
  end

  chain :with_vnics do |vnic_array|
    @vnics = vnic_array
  end

  match do |nfa|
    @nfa = nfa
    secg_id = secg.canonical_uuid

    expect_chains("ebtables", l2_chains_for_secg(secg_id)) &&
    expect_chains("iptables", l3_chains_for_secg(secg_id)) &&
    ( @vnics.nil? || (
      @vnics.each {|v| raise "VNic '#{v.canonical_uuid}' doesn't have a direct ip lease." if v.direct_ip_lease.first.nil?}
      expect_rules("ebtables", "vdc_#{secg_id}_isolation", l2_iso_rules) &&
      expect_rules("iptables", "vdc_#{secg_id}_isolation", l3_iso_rules)
    ))
  end

  failure_message_for_should {|nfa| @fail_should}
  failure_message_for_should_not {|nfa| @fail_should_not}
end

RSpec::Matchers.define :have_nothing_applied do
  match do |nfa|
    nfa.is_empty?("iptables") &&
    nfa.is_empty?("ebtables")
  end
end