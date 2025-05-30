package utils
import data.abac_am
import future.keywords.in
import future.keywords.if

user_can_access_schema(user_id, catalog_name, schema_name) if {
    #user_has_access_to_at_least_one_table(user_id, catalog_name, schema_name)

    some role in role_assign[user_id]
    some grant in role_data[role]
    catalog_name == grant.catalog

}

user_has_access_to_at_least_one_table(user_id, catalog_name, schema_name) if {
    #tables_of_schema := abac_am.all_tables_in_schema(catalog_name, schema_name)
    #some table_obj in tables_of_schema
    #user_can_access_table(user_id, catalog_name, schema_name, table_obj.table_name)

    some role in role_assign[user_id]
    some grant in role_data[role]
    catalog_name == grant.catalog

}

role_assign :=
    {
        "srv.sys_customer": ["rl.rep_customer"],
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
