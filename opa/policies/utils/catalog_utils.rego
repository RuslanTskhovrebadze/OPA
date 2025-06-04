package utils
import data.abac_am
import future.keywords.in
import future.keywords.contains
import future.keywords.if
#import data.policies
#import data.policies

#user_can_access_catalog(user_id, catalog_name) if {
#    catalog_name in abac_am.user_catalogs(user_id)
#}


#user_catalogs(user_id) := returned_user_catalogs if {
#    returned_user_attributes := user_attributes(user_id)
#    returned_user_catalogs = returned_user_attributes["catalogs"]
#}

user_can_access_catalog(_, catalog_name) if {
    catalog_name in user_catalogs
}

user_catalogs contains got_catalog if {
    some user_id, roles in role_assign
    some i,j
    got_catalog := role_data[roles[j]][i].catalog
}

#user_can_access_catalog(user_id, catalog_name) if {
    #user_id in ["scott","srv.sys_customer"]
    #catalog_name in ["datalake"]

#    some role in role_assign[user_id]
#    some grant in role_data[role]
#    catalog_name == grant.catalog
#}

role_assign :=
    {
        "srv.sys_customer": ["rl.rep_customer"],
        "scott": ["rl.rep_customer"],
        "srv.sys_orders": ["rl.rep_orders"],
        "bus_analyst": ["rl.edw_ba"],
        "sys_analyst": ["rl.analyst"]
    }
    
role_data :=
{
        "rl.rep_customer": [
                {
                    "action": "read",
                    "table": "tdh_rep.customer",
                    "catalog": "datalake"
                },
                {
                    "action": "read",
                    "table": "tdh_rep.fct_A1",
                    "catalog": "datalake"
                }       
             ]
}


