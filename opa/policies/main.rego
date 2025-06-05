package policies

import data.rbac_data
import data.role_assignment
import data.role_grant


import data.abac_am
import data.access
import data.admin
import data.cms
import data.rls
import data.utils
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

# ----------------------------------------------
# That section handle the policies for the regular user
allow if {
	#abac_am.if_user_exists(utils.user_id)
	#access.allow_resource
	allow_resource
}


#-----Перенос логики в один файл-----
allow_resource if {
	access.allow_default_access
}

allow_resource if {
	operation := input.action.operation
	resource := input.action.resource
	allow_for_resource(operation, resource)
}

allow_for_resource(operation, resource) if {
    access.allow_for_resource_catalog(operation, resource)
}

#allow_for_resource(operation, resource) if {
#    access.allow_for_resource_schema(operation, resource)
#}

#allow_for_resource(operation, resource) if {
#    access.allow_for_resource_table(operation, resource)
#}


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

columnMask := column_mask if {
	column_mask := cms.mask
}

rowFilters contains row_filter if {
	row_filter := rls.filter
}
