package policies

role_data :=
{
        "rl.rep_customer": [
                {
                    "action": "read",
                    "table": "tdh_rep.customer",
                    "catalog: "datalake"
                },
                {
                    "action": "read",
                    "table": "tdh_rep.fct_A1",
                    "catalog: "datalake"
                }       
             ],
         "rl.rep_orders": [
                {
                    "action": "read",
                    "table": "tdh_rep.orders",
                    "catalog: "datalake"
                }
              ],
         "rl.edw_ba": [
                {
                    "action": "read",
                    "table": "tdh_em.part",
                    "catalog: "datalake"
                }
              ],
          "rl.analyst": [
                {
                    "action": "read",
                    "table": "tdh_em.part",
                    "catalog: "datalake"
                },
                {
                    "action": "read",
                    "table": "tdh_rv.partsupp",
                    "catalog: "datalake"
                },
                {
                    "action": "read",
                    "table": "tdh_rep.orders",
                    "catalog: "datalake"
                },
                {
                    "action": "read",
                    "table": "tdh_rep.orders",
                    "catalog: "datalake"
                }
              ]
     }
