# -*- coding: utf-8 -*-

module Dcmgr
  module VNet
    module OpenFlow

      class OpenFlowNetwork
        include Dcmgr::Logger
        include OpenFlowConstants

        attr_reader :id
        attr_reader :datapath

        # Add _numbers postfix.
        attr_reader :ports
        attr_reader :local_ports

        attr_reader :subnet_macs

        # Use the actual network db object instead.
        attr_accessor :virtual
        attr_accessor :domain_name
        attr_accessor :local_hw
        attr_accessor :ipv4_network
        attr_accessor :ipv4_gw
        attr_accessor :prefix

        attr_reader :services
        attr_accessor :packet_handlers

        def initialize dp, id
          @id = id
          @datapath = dp
          @ports = []
          @local_ports = []
          @subnet_macs = []

          @virtual = false
          @prefix = 0

          @services = {}
          @packet_handlers = []
        end

        def update
          datapath.add_flows(flood_flows)
        end

        def add_port port, is_local
          ports << port
          local_ports << port if is_local
        end

        def remove_port port
          ports.delete port
          local_ports.delete port
        end

        def flood_flows
          @flood_flows ||= Array.new
        end

        def install_virtual_network(eth_port)
          flood_flows << Flow.new(TABLE_VIRTUAL_DST, 0, {:reg1 => id, :dl_dst => 'ff:ff:ff:ff:ff:ff'}, :for_each => [local_ports, {:output => :placeholder}])
          flood_flows << Flow.new(TABLE_VIRTUAL_DST, 1,
                                  {:reg1 => id, :reg2 => 0, :dl_dst => 'ff:ff:ff:ff:ff:ff'},
                                  {:for_each => [ports, {:output => :placeholder}], :for_each2 => [subnet_macs, {:mod_dl_dst => :placeholder, :output => eth_port}]})

          learn_arp_match = "priority=#{1},idle_timeout=#{3600*10},table=#{TABLE_VIRTUAL_DST},reg1=#{id},reg2=#{0},NXM_OF_ETH_DST[]=NXM_OF_ETH_SRC[]"
          learn_arp_actions = "output:NXM_NX_REG2[]"

          flows = []

          # Pass packets to the dst table if it originates from an instance on this host. (reg2 == 0)
          flows << Flow.new(TABLE_VIRTUAL_SRC, 6, {:arp => nil, :reg1 => id, :reg2 => 0}, {:drop => nil})
          flows << Flow.new(TABLE_VIRTUAL_SRC, 4, {:reg1 => id, :reg2 => 0}, {:drop => nil})
          # If from an external host, learn the ARP for future use.
          flows << Flow.new(TABLE_VIRTUAL_SRC, 2, {:reg1 => id, :arp => nil}, [{:learn => "#{learn_arp_match},#{learn_arp_actions}"}, {:resubmit => TABLE_VIRTUAL_DST}])
          # Default action is to pass the packet to the dst table.
          flows << Flow.new(TABLE_VIRTUAL_SRC, 0, {:reg1 => id}, {:resubmit => TABLE_VIRTUAL_DST})

          # Catch ARP for the DHCP server.
          flows << Flow.new(TABLE_VIRTUAL_DST, 3, {:reg1 => id, :arp => nil, :nw_dst => services[:dhcp].ip.to_s}, {:controller => nil})

          # Catch DHCP requests.
          flows << Flow.new(TABLE_VIRTUAL_DST, 3, {:reg1 => id, :udp => nil, :dl_dst => services[:dhcp].mac, :nw_dst => services[:dhcp].ip.to_s, :tp_src => 68, :tp_dst => 67}, {:controller => nil})
          flows << Flow.new(TABLE_VIRTUAL_DST, 3, {:reg1 => id, :udp => nil, :dl_dst => 'ff:ff:ff:ff:ff:ff', :nw_dst => '255.255.255.255', :tp_src => 68, :tp_dst => 67}, {:controller => nil})

          datapath.add_flows flows
        end

        def install_physical_network
          flood_flows << Flow.new(TABLE_MAC_ROUTE,      1, {:dl_dst => 'FF:FF:FF:FF:FF:FF'}, :for_each => [ports, {:output => :placeholder}])
          flood_flows << Flow.new(TABLE_ROUTE_DIRECTLY, 1, {:dl_dst => 'FF:FF:FF:FF:FF:FF'}, :for_each => [ports, {:output => :placeholder}])
          flood_flows << Flow.new(TABLE_LOAD_DST,       1, {:dl_dst => 'FF:FF:FF:FF:FF:FF'}, :for_each => [ports, {:load_reg0 => :placeholder, :resubmit => TABLE_LOAD_SRC}])
          flood_flows << Flow.new(TABLE_ARP_ROUTE,      1, {:arp => nil, :dl_dst => 'FF:FF:FF:FF:FF:FF', :arp_tha => '00:00:00:00:00:00'}, :for_each => [ports, {:output => :placeholder}])
        end

        def add_gre_tunnel name, remote_ip
          ovs_ofctl = datapath.ovs_ofctl
          tunnel_name = "t-#{name}-#{id}"

          command = "#{ovs_ofctl.ovs_vsctl} add-port #{ovs_ofctl.switch_name} #{tunnel_name} -- set interface #{tunnel_name} type=gre options:remote_ip=#{remote_ip} options:key=#{id}"

          logger.info "Adding GRE tunnel: '#{command}'."
          system(command)
        end

        def install_mac_subnet eth_port, broadcast_addr
          logger.info "Installing mac subnet: broadcast_addr:#{broadcast_addr}."

          flows = []
          flows << Flow.new(TABLE_CLASSIFIER, 7, {:dl_dst => broadcast_addr}, {:drop => nil })
          flows << Flow.new(TABLE_VIRTUAL_SRC, 8, {:dl_dst => broadcast_addr}, {:drop => nil })

          flood_flows << Flow.new(TABLE_CLASSIFIER, 8, {:in_port => eth_port, :dl_dst => broadcast_addr}, {:mod_dl_dst => 'ff:ff:ff:ff:ff:ff', :load_reg1 => id, :load_reg2 => eth_port, :resubmit => TABLE_VIRTUAL_SRC})

          datapath.add_flows flows
        end

        def external_mac_subnet broadcast_addr
          logger.info "Adding external mac subnet: broadcast_addr:#{broadcast_addr}."

          subnet_macs << broadcast_addr

          flows = []
          flows << Flow.new(TABLE_CLASSIFIER, 7, {:dl_dst => broadcast_addr}, {:drop => nil })
          flows << Flow.new(TABLE_VIRTUAL_SRC, 8, {:dl_dst => broadcast_addr}, {:drop => nil })

          datapath.add_flows flows
        end
      end

    end
  end
end
