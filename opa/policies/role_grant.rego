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
                    "schema": "sf1"
                    "table": "customer",
                    "catalog": "tpch"
                }       
             ],
         "rl.rep_orders": [
                {
                    "action": "read",
                    "table": "tdh_rep.orders",
                    "catalog": "tpcds"
                }
              ],
         "rl.edw_ba": [
                {
                    "action": "read",
                    "table": "tdh_em.part",
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
                }
              ]
     }
