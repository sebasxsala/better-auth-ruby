# frozen_string_literal: true

module BetterAuth
  module MigrationPlan
    TableChange = Struct.new(:logical_name, :table_name, :table, :order, keyword_init: true)
    FieldChange = Struct.new(:logical_name, :table_name, :fields, :table, :order, keyword_init: true)
    IndexChange = Struct.new(:table_name, :field_name, :name, :unique, :field, keyword_init: true)

    Plan = Struct.new(:to_create, :to_add, :to_index, :warnings, :dialect, :tables, keyword_init: true) do
      def empty?
        to_create.empty? && to_add.empty? && to_index.empty?
      end
    end
  end
end
