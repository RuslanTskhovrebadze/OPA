package utils
import data.abac_am
import future.keywords.in
import future.keywords.if
import data.policies.role_assignment
import data.policies.role_grant

user_can_access_catalog(user_id, catalog_name) if {
    #catalog_name in abac_am.user_catalogs(user_id)

    some role in role_assign[user_id]
    some grant in role_data[role]
    catalog_name == grant.catalog
}

