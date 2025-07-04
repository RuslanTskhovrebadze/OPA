package policies

import data.rbac_data
import data.role_assignment
import data.role_grant

import data.admin
import future.keywords.every

#import data.abac_am
#import data.access
#import data.cms
#import data.rls
#import data.abac_am
#import data.utils

import future.keywords.contains
import future.keywords.if
import future.keywords.in
import input


#  ----------------------------------------------
# That section handle the policies for the admin user
allow if {
	# abac_am.if_user_exists(input.context.identity.user)
	trace("inside admin")
	admin.allow_admin
}

test_data := {"rules" : [{"super_user": "ruslan"}]}

allow if {
	#input.context.identity.user == test_data.rules[0]["super_user"]
	input.context.identity.user ==  rules_data.rules[0]["super_user"]
}

#Для Minio
# Allow the root user to perform any action.
allow if {
 input.owner == true
}

allow if {
    input.action == "s3:GetBucketLocation"
    #input.groups == "read_group"
    #input.conditions.userid == ["david"]
    input.userid == ["david"]
}

allow if {
    #input.action == "s3:GetObject"
    #input.resource == "datalake/*" #"arn:aws:s3:::
    #input.bucket == "datalake"
    #input.conditions.userid == ["david"]
    input.userid == ["david"]
}

allow if {
    #input.action == "s3:ListBucket"
    #input.bucket == "datalake"
    #input.conditions.userid == ["david"]
    input.userid == ["david"]
}


#allow if {
#    input.action == "s3:GetBucketLocation"
#    input.action == "s3:PutBucketPolicy"
#    input.action == "s3:GetBucketPolicy"
#    input.action == "s3:DeleteBucketPolicy"
#    input.action == "s3:ListAllMyBuckets"
#    input.action == "s3:ListBucket"
#    #input.resource == "arn:aws:s3:::datalake/*"
#}



# All other users may do anything other than call PutObject
#allow {
# input.action != "s3:PutObject"
# input.owner == false
#}






# ----------------------------------------------
# That section handle the policies for the regular user
allow if {
	#abac_am.if_user_exists(utils.user_id)
	#access.allow_resource
	allow_resource
}

#-----Перенос логики в один файл-----
allow_resource if {
    allow_default_access
}

allow_default_access if {
    allow_execute_query
}

allow_execute_query if {
	#abac_am.if_user_exists(utils.user_id)
	input.action.operation == "ExecuteQuery"
}

allow_resource if {
	operation := input.action.operation
	resource := input.action.resource
	allow_for_resource(operation, resource)
}

allow_for_resource(operation, resource) if {
    allow_for_resource_catalog(operation, resource)
}

input_user_id := input.context.identity.user

allow_for_resource_catalog(operation, resource) if {
    operation == "AccessCatalog"
    user_can_access_catalog(input_user_id, resource.catalog.name)
}

allow_for_resource_catalog(operation, resource) if {
    operation == "ShowSchemas"
    user_can_access_catalog(input_user_id, resource.catalog.name)
}

allow_for_resource_catalog(operation, resource) if {
    operation == "FilterCatalogs"
    user_can_access_catalog(input_user_id, resource.catalog.name)
}

user_can_access_catalog(_, catalog_name) if {
    catalog_name in user_catalogs
}

user_catalogs contains got_catalog if {
    some user_id, roles in role_assign
    some i,j
    user_id == input_user_id
    got_catalog := role_data[roles[j]][i].catalog
}

allow_for_resource(operation, resource) if {
    allow_for_resource_schema(operation, resource)
}

allow_for_resource_schema(operation, resource) if {
    operation == "ShowTables"
    catalog_name := resource.schema.catalogName
    schema_name := resource.schema.schemaName
    user_can_access_schema(input_user_id , catalog_name, schema_name)
}

allow_for_resource_schema(operation, resource) if {
    operation == "FilterSchemas"
    catalog_name := resource.schema.catalogName
    schema_name := resource.schema.schemaName
    user_can_access_schema(input_user_id , catalog_name, schema_name)
}

user_can_access_schema(_, catalog_name, schema_name) if {
    schema_name in user_schemas
    catalog_name in user_catalogs

}

user_schemas contains schemas if {
    some user_id, roles in role_assign
    some i,j
    user_id == input_user_id
    schemas := role_data[roles[j]][i].schema
}


allow_for_resource(operation, resource) if {
    allow_for_resource_table(operation, resource)
}

allow_for_resource_table(operation, resource) if {
    operation in ["SelectFromColumns","FilterTables","ShowColumns","FilterColumns"]
    catalog_name := resource.table.catalogName
    schema_name := resource.table.schemaName
    table_name := resource.table.tableName
    
    schema_name in user_schemas
    catalog_name in user_catalogs
    table_name in user_tables
}

user_tables contains tables if {
    some user_id, roles in role_assign
    some i,j
    user_id == input_user_id
    tables := role_data[roles[j]][i].table
}

allow_for_resource_table(operation, resource) if {
    operation == "SelectFromColumns"
    user_can_access_catalog(input_user_id, resource.table.catalogName)
    resource.table.schemaName == "information_schema"
	resource.table.tableName == "schemata"
}

allow_for_resource_table(operation, resource) if { 
    operation == "SelectFromColumns"
    catalog_name := resource.table.catalogName
    #schema_name := resource.table.schemaName
    #table_name := resource.table.tableName
	user_can_access_catalog(input_user_id, catalog_name)
    resource.table.schemaName == "information_schema"
    resource.table.tableName in ["columns", "tables"]
}


# ----------------------------------------------

# ----------------------------------------------
# That handle the generic case of batch operations

batch contains i if {
	some i
	raw_resource := input.action.filterResources[i]
	allow with input.action.resource as raw_resource
}

# Corner case: filtering columns is done with a single table item, and many columns inside
# We cannot use our normal logic in other parts of the policy as they are based on sets
# and we need to retain order
#batch contains i if {
#	trace("inside another batch")
#	some i
#	input.action.operation == "FilterColumns"
#	count(input.action.filterResources) == 1
#	raw_resource := input.action.filterResources[0]
#	count(raw_resource.table.columns) > 0
#	new_resources := [
#	object.union(raw_resource, {"table": {"column": column_name}}) |
#		column_name := raw_resource.table.columns[_]
#	]
#	allow with input.action.resource as new_resources[i]
#}

#columnMask := column_mask if {
#	column_mask := cms.mask
#}

#rowFilters contains row_filter if {
#	row_filter := rls.filter
#}

#-----------
allow_default_access if {
    allow_access_catalog_on_system_catalog
}

allow_default_access if {
    allow_sfc_on_system_catalog
}

allow_default_access if {
    allow_system_catalog_jdbc_schema_tables_table
}

allow_default_access if {
    allow_sfc_on_table_schemas_in_system_catalog
}

allow_default_access if {
    allow_sfc_on_table_columns_in_system_catalog
}

allow_execute_query if {
	#abac_am.if_user_exists(utils.user_id)
	input.action.operation == "ExecuteQuery"
}

# Will run if you'll try to use the dbeaver's GUI
allow_access_catalog_on_system_catalog if {
	input.action.operation == "AccessCatalog"
	input.action.resource.catalog.name == "system"
}

# Will run if you'll try to use the dbeaver's GUI
allow_sfc_on_system_catalog if {
	input.action.operation == "SelectFromColumns"
	input.action.resource.table.catalogName == "system"
        input.action.resource.table.schemaName = "jdbc"
	input.action.resource.table.tableName in ["catalogs", "types"]
}

allow_system_catalog_jdbc_schema_tables_table if {
    input.action.operation == "SelectFromColumns"
    input.action.resource.table.catalogName = "system"
    input.action.resource.table.schemaName = "jdbc"
    input.action.resource.table.tableName = "tables"
}

# Will run if you'll try to use the dbeaver's GUI
allow_sfc_on_table_schemas_in_system_catalog if {
	input.action.operation == "SelectFromColumns"
	input.action.resource.table.catalogName == "system"
	input.action.resource.table.schemaName = "jdbc"
	input.action.resource.table.tableName == "schemas"
}

allow_sfc_on_table_columns_in_system_catalog if {
    input.action.operation == "SelectFromColumns"
    input.action.resource.table.catalogName = "system"
    input.action.resource.table.schemaName = "jdbc"
    input.action.resource.table.tableName = "columns"
}
