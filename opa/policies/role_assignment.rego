package policies

role_assign :=
    {
        "srv.sys_customer": ["rl.rep_A"],
        "srv.sys_orders": ["rl.rep_orders"],
        "bus_analyst": ["rl.edw_ba"],
        "sys_analyst": ["rl.analyst"]
    }
