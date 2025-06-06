package policies

role_data :=
{
        "rl.rep_customer": [
                {
                    "action": "read",
                    "schema": "tdh_rep",
                    "table": "customer",
                    "catalog": "datalake"
                },
                {
                    "action": "read",
                    "schema": "sf1",
                    "table": "customer",
                    "catalog": "tpch"
                },
                {
                    "action": "read",
                    "schema": "sample",
                    "table": "supplier",
                    "catalog": "datalake"
                } 
             ],
         "rl.rep_orders": [
                {
                    "action": "read",
                    "schema": "tdh_rep",
                    "table": "orders",
                    "catalog": "datalake"
                }
              ],
         "rl.edw_ba": [
                {
                    "action": "read",
                    "schema": "tdh_em",
                    "table": "part",
                    "catalog": "datalake"
                }
              ],
          "rl.analyst": [
                {
                    "action": "read",
                    "table": "tdh_em.part",
                    "catalog": "datalake"
                },
                {
                    "action": "read",
                    "table": "tdh_rv.partsupp",
                    "catalog": "datalake"
                },
                {
                    "action": "read",
                    "table": "tdh_rep.orders",
                    "catalog": "datalake"
                },
                {
                    "action": "read",
                    "table": "tdh_rep.orders",
                    "catalog": "tpch"
                },
                {
                    "action": "read",
                    "schema": "tdh_rv",
                    "table": "orders",
                    "catalog": "tpcds"
                }
              ]
     }
