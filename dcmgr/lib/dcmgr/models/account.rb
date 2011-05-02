# -*- coding: utf-8 -*-

module Dcmgr::Models
  class Account < BaseNew
    taggable 'a'
    # pk has to be overwritten by the STI subclasses.
    unrestrict_primary_key

    DISABLED=0
    ENABLED=1
    
    inheritable_schema do
      String :description, :size=>100
      Fixnum :enabled, :default=>ENABLED, :null=>false
    end
    with_timestamps

    one_to_many  :tags, :dataset=>lambda { Tag.filter(:account_id=>self.canonical_uuid); }
    one_to_one :quota, :class=>Quota, :key=>:account_id

    # sti plugin has to be loaded at lower position.
    plugin :subclasses
    plugin :single_table_inheritance, :uuid, :model_map=>{}
    

    def disable?
      self.enabled == DISABLED
    end

    def enable?
      self.enabled == ENABLED
    end

    def after_create
      self.quota = Quota.create
      super
    end
    

    # STI class variable setter, getter methods.
    class << self
      def default_values
        @default_values ||= {}
      end

      def pk(pk=nil)
        if pk
          default_values[:id] = pk
        end
        default_values[:id]
      end
      
      def uuid(uuid=nil)
        if uuid.is_a?(String)
          uuid = uuid.downcase
          unless self.check_trimmed_uuid_format(uuid)
            raise "Invalid syntax of uuid: #{uuid}"
          end
          default_values[:uuid] = uuid
        end
        raise("#{self}.uuid is unset. Set the unique number") unless default_values[:uuid]
        "#{uuid_prefix}-#{default_values[:uuid]}"
      end

      def description(description=nil)
        if description
          default_values[:description] = description
        end
        default_values[:description]
      end
    end

    module SystemAccount
      def self.define_account(class_name, &blk)
        unless class_name.is_a?(Symbol) || class_name.is_a?(String)
          raise ArgumentError
        end

        c = Class.new(Account, &blk)
        self.const_set(class_name.to_sym, c)
        Account.sti_model_map[c.uuid] = c
        Account.sti_key_map[c.to_s] = c.uuid
        c
      end
    end

    install_data_hooks do
      Account.subclasses.each { |m|
        Account.create(m.default_values.dup)
      }

      # create shared resource pool tags
      Dcmgr::Tags::HostPool.create(:account_id=>SystemAccount::SharedPoolAccount.uuid,
                                   :uuid=>'shhost',
                                   :name=>"default_shared_hosts")
      Dcmgr::Tags::NetworkPool.create(:account_id=>SystemAccount::SharedPoolAccount.uuid,
                                      :uuid=>'shnet',
                                      :name=>"default_shared_networks")
      Dcmgr::Tags::StoragePool.create(:account_id=>SystemAccount::SharedPoolAccount.uuid,
                                      :uuid=>'shstor',
                                      :name=>"default_shared_storages")
    end
    
    SystemAccount.define_account(:DatacenterAccount) do
      pk 100
      uuid '00000000'
      description 'datacenter system account'

      # DatacenterAccount never be disabled
      def before_save
        super
        self.enabled = Account::ENABLED
      end
    end

    SystemAccount.define_account(:SharedPoolAccount) do
      pk 101
      uuid 'shpoolxx'
      description 'system account for shared resources'

      # SahredPoolAccount is always enabled.
      def before_save
        super
        self.enabled = Account::ENABLED
      end
    end
    
  end
end

