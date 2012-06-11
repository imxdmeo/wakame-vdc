# -*- coding: utf-8 -*-
module Hijiki::DcmgrResource::V1203
  module BackupObjectMethods
    def self.included(base)
      base.extend(ClassMethods)
    end
    
    module ClassMethods
      def list(params = {})
        data = self.find(:all, :params => params)
        #results = []
        #data.each { |row|
        #  results << row.attributes
        #}
      end

      def show(uuid)
        self.get(uuid)
      end
      
      def create(params)
        snapshot = self.new
        snapshot.volume_id = params[:volume_id]
        snapshot.destination = params[:destination]
        snapshot.display_name = params[:display_name]
        snapshot.save
        snapshot
      end
      
      def destroy(snapshot_id)
        self.delete(snapshot_id).body
      end
      
      def status(account_id)
        @collection ||= self.collection_name
        self.collection_name = File.join(@collection,account_id)
        result = self.get(:status)
        self.collection_name = @collection
        result
      end
    end    
  end

  class BackupObject < Base
    include BackupObjectMethods
  end

  BackupObject.preload_resource('Result', Module.new {
    def storage_node
      attributes['storage_node'] ||= StorageNode.find(attributes['storage_node_id'])
    end
  })
end