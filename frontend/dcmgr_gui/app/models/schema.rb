# -*- coding: utf-8 -*-
require 'sequel'
require 'yaml'
require 'erb'

module Schema
  extend self
  
  def current_connect
    Sequel::DATABASES.first
  end
  
  def config(env,file)
    YAML::load(ERB.new(IO.read(file)).result)[env]
  end
    
  attr_reader :db
  def table_exists?(table_name)
    current_connect.table_exists? table_name
  end

  def create!
    Sequel::MySQL.default_charset = 'utf8'
    Sequel::MySQL.default_engine = 'InnoDB'

    models.each { |model|
      model.create_table!
    }
    current_connect.create_table? :users_accounts do
      primary_key :id, :type=>Integer
      Fixnum :user_id, :null => false
      Fixnum :account_id, :null => false
    end
  end

  def drop!
    models.each { |model|
      current_connect.drop_table(model.table_name)
    }
  end
  
  def models
    @models ||= [Account, User,
                 Authz,Tag,TagMapping,Information
                ].freeze
  end
end
