use crate::{
    budget::{AsBudget, Budget},
    host::metered_clone::{MeteredClone, MeteredIterator},
    host::metered_xdr::metered_write_xdr,
    xdr::{ContractCostType, ScMap, ScMapEntry, ScVal},
    Env, Host, HostError, Symbol, Val,
};
use expect_test::{self, expect};
use soroban_env_common::xdr::{ScErrorCode, ScErrorType};
use soroban_test_wasms::VEC;

#[test]
fn xdr_object_conversion() -> Result<(), HostError> {
    let host = Host::test_host()
        .test_budget(100_000, 100_000)
        .enable_model(ContractCostType::HostMemCpy, 1, 0, 1, 0);
    let scmap: ScMap = host.map_err(
        vec![
            ScMapEntry {
                key: ScVal::U32(1),
                val: ScVal::U32(2),
            },
            ScMapEntry {
                key: ScVal::U32(2),
                val: ScVal::U32(4),
            },
        ]
        .try_into(),
    )?;
    host.to_host_val(&ScVal::Map(Some(scmap)))?;
    host.with_budget(|budget| {
        // 2 iterations, 1 for the vec cpy, 1 for the bulk bytes cpy
        assert_eq!(budget.get_tracker(ContractCostType::HostMemCpy)?.0, 2);
        // 72 bytes copied for the ScVal->Val conversion: 24 (Vec bytes) + 2 (map entries) x (8 (padding bytes) + 8 (key bytes) + 8 (val bytes))
        assert_eq!(
            budget.get_tracker(ContractCostType::HostMemCpy)?.1,
            Some(72)
        );
        Ok(())
    })?;
    Ok(())
}

#[test]
fn vm_hostfn_invocation() -> Result<(), HostError> {
    let host = Host::test_host_with_recording_footprint();
    let id_obj = host.register_test_contract_wasm(VEC);
    // this contract requests initial pages = 16 worth of linear memory, not sure why
    let host = host
        .test_budget(100_000, 1_048_576)
        .enable_model(ContractCostType::InvokeVmFunction, 10, 0, 1, 0)
        .enable_model(ContractCostType::DispatchHostFunction, 10, 0, 1, 0);

    // `vec_err` is a test contract function which calls `vec_new` (1 call)
    // and `vec_put` (1 call) so total input of 2 to the budget from `CostType::DispatchHostFunction`.
    let sym = Symbol::try_from_small_str("vec_err").unwrap();
    let args = host.test_vec_obj::<u32>(&[1])?;

    // try_call
    host.try_call(id_obj, sym, args)?;
    host.with_budget(|budget| {
        assert_eq!(budget.get_tracker(ContractCostType::InvokeVmFunction)?.0, 1);
        assert_eq!(
            budget
                .get_tracker(ContractCostType::DispatchHostFunction)?
                .0,
            2
        );
        assert_eq!(budget.get_cpu_insns_consumed()?, 30);
        assert_eq!(budget.get_mem_bytes_consumed()?, 3);
        Ok(())
    })?;

    Ok(())
}

#[test]
fn test_vm_fuel_metering() -> Result<(), HostError> {
    use super::util::wasm_module_with_4n_insns;
    let host = Host::test_host_with_recording_footprint();
    let id_obj = host.register_test_contract_wasm(&wasm_module_with_4n_insns(1000));
    let host = host
        .test_budget(100_000, 1_048_576)
        .enable_model(ContractCostType::WasmInsnExec, 6, 0, 0, 0)
        .enable_model(ContractCostType::WasmMemAlloc, 0, 0, 1, 0);

    let sym = Symbol::try_from_small_str("test").unwrap();
    let args = host.test_vec_obj::<u32>(&[4375])?;

    // try_call
    host.call(id_obj, sym, args)?;
    host.with_budget(|budget| {
        assert_eq!(budget.get_tracker(ContractCostType::WasmInsnExec)?.0, 4005);
        assert_eq!(budget.get_tracker(ContractCostType::WasmMemAlloc)?.0, 65536);
        assert_eq!(budget.get_cpu_insns_consumed()?, 24030);
        assert_eq!(budget.get_mem_bytes_consumed()?, 65536);
        Ok(())
    })?;
    Ok(())
}

#[test]
fn metered_xdr() -> Result<(), HostError> {
    let host = Host::test_host()
        .test_budget(100_000, 100_000)
        .enable_model(ContractCostType::ValSer, 0, 10, 0, 1)
        .enable_model(ContractCostType::ValDeser, 0, 10, 0, 1);
    let scmap: ScMap = host.map_err(
        vec![
            ScMapEntry {
                key: ScVal::U32(1),
                val: ScVal::U32(2),
            },
            ScMapEntry {
                key: ScVal::U32(2),
                val: ScVal::U32(4),
            },
        ]
        .try_into(),
    )?;
    let mut w = Vec::<u8>::new();
    metered_write_xdr(host.budget_ref(), &scmap, &mut w)?;
    host.with_budget(|budget| {
        assert_eq!(
            budget.get_tracker(ContractCostType::ValSer)?.1,
            Some(w.len() as u64)
        );
        Ok(())
    })?;

    host.metered_from_xdr::<ScMap>(w.as_slice())?;
    host.with_budget(|budget| {
        assert_eq!(
            budget.get_tracker(ContractCostType::ValDeser)?.1,
            Some(w.len() as u64)
        );
        Ok(())
    })?;
    Ok(())
}

#[test]
fn metered_xdr_out_of_budget() -> Result<(), HostError> {
    let host =
        Host::test_host()
            .test_budget(10, 10)
            .enable_model(ContractCostType::ValSer, 0, 10, 0, 1);
    let scmap: ScMap = host.map_err(
        vec![
            ScMapEntry {
                key: ScVal::U32(1),
                val: ScVal::U32(2),
            },
            ScMapEntry {
                key: ScVal::U32(2),
                val: ScVal::U32(4),
            },
        ]
        .try_into(),
    )?;
    let mut w = Vec::<u8>::new();
    let res = metered_write_xdr(host.budget_ref(), &scmap, &mut w);
    let code = (ScErrorType::Budget, ScErrorCode::ExceededLimit);
    assert!(HostError::result_matches_err(res, code));
    Ok(())
}

#[test]
fn map_insert_key_vec_obj() -> Result<(), HostError> {
    let mut host = Host::test_host().test_budget(1000, 1000);
    let mut m = host.map_new()?;
    let k0 = host.test_vec_obj(&[2, 3])?;
    let v0: Val = 6_u32.into();
    let k1 = host.test_vec_obj(&[5, 6, 7])?;
    let v1: Val = 8_u32.into();
    m = host.map_put(m, k0.into(), v0)?;

    // now we enable various cost models
    host = host
        .enable_model(ContractCostType::VisitObject, 10, 0, 1, 0)
        .enable_model(ContractCostType::MapEntry, 10, 0, 1, 0);
    host.map_put(m, k1.into(), v1)?;

    host.with_budget(|budget| {
        // 6 = 2 visits to ensure object handle integrity + 1 visit map + 1
        // visit k1 + (obj_cmp which needs to) 1 visit both k0 and k1 during
        // lookup, and then 2 more to validate order of resulting map.
        assert_eq!(budget.get_tracker(ContractCostType::VisitObject)?.0, 8);
        // upper bound of number of map-accesses, counting both binary-search, point-access and validate-scan.
        assert_eq!(budget.get_tracker(ContractCostType::MapEntry)?.0, 8);
        Ok(())
    })?;

    Ok(())
}

#[test]
fn test_recursive_type_clone() -> Result<(), HostError> {
    let host = Host::test_host()
        .test_budget(100000, 100000)
        .enable_model(ContractCostType::HostMemAlloc, 10, 0, 1, 0)
        .enable_model(ContractCostType::HostMemCpy, 10, 0, 1, 0);
    let scmap: ScMap = host.map_err(
        vec![
            ScMapEntry {
                key: ScVal::U32(1),
                val: ScVal::U32(2),
            },
            ScMapEntry {
                key: ScVal::U32(2),
                val: ScVal::U32(4),
            },
        ]
        .try_into(),
    )?;
    let v: Vec<Box<ScMap>> = vec![
        Box::new(scmap.clone()),
        Box::new(scmap.clone()),
        Box::new(scmap),
    ];

    v.metered_clone(host.as_budget())?;

    //*********************************************************************************************************************************************/
    /* Type(size, count) | Vec(24,1) ---> Box(8,3) ----> ScMap(24,3) --> Vec(24,3) ----> ScMapEntry(128,6) --> ScVal(64, 12) --> U32(4, 12)        */
    /* MemAlloc          |            8x3      +    24x3              +             128x6                                                    = 864 */
    /* MemCpy            |  24    +   8x3      +    24x3              +             128x6                                                    = 888 */
    //*********************************************************************************************************************************************/
    expect!["864"].assert_eq(
        host.as_budget()
            .get_tracker(ContractCostType::HostMemAlloc)?
            .1
            .unwrap()
            .to_string()
            .as_str(),
    );
    // 600 = 576 + 24 is correct because we need to copy all the memory allocated, as well as the
    // memory layout of the top level type (Vec).
    expect!["888"].assert_eq(
        host.as_budget()
            .get_tracker(ContractCostType::HostMemCpy)?
            .1
            .unwrap()
            .to_string()
            .as_str(),
    );
    Ok(())
}

#[test]
fn test_metered_collection() -> Result<(), HostError> {
    let budget = Budget::default();
    let v: Vec<i32> = vec![1, 2, -3, 4, -6, -11];
    let res = v
        .iter()
        .filter(|i| i.abs() > 3)
        .map(|i| Ok(i.abs() as u64))
        .metered_collect::<Result<Vec<u64>, HostError>>(&budget)??;
    assert_eq!(res, vec![4, 6, 11]);
    Ok(())
}

// This test is a sanity check to make sure we didn't accidentally change the cost schedule.
// If the cost schedule have changed, need to update this test by running
// `UPDATE_EXPECT=true cargo test`
#[test]
fn total_amount_charged_from_random_inputs() -> Result<(), HostError> {
    let host = Host::default();

    let tracker: Vec<(u64, Option<u64>)> = vec![
        (246, None),
        (184, None),
        (1, Some(152)),
        (1, Some(65)),
        (1, Some(74)),
        (176, None),
        (97, None),
        (1, Some(49)),
        (1, Some(103)),
        (1, Some(193)),
        (226, None),
        (250, None),
        (186, None),
        (1, Some(227)),
        (1, Some(69)),
        (1, Some(160)),
        (1, Some(147)),
        (1, Some(147)),
        (47, None),
        (1, Some(1)),
        (1, None),
        (1, None),
        (1, None),
        (1, None),
        (1, None),
        (1, None),
        (1, None),
        (1, None),
    ];

    for ty in ContractCostType::variants() {
        host.with_budget(|b| b.bulk_charge(ty, tracker[ty as usize].0, tracker[ty as usize].1))?;
    }
    let actual = format!("{:?}", host.as_budget());
    expect![[r#"
        =====================================================================================================================================================================
        Cpu limit: 100000000; used: 10115314
        Mem limit: 104857600; used: 276044
        =====================================================================================================================================================================
        CostType                 iterations     input          cpu_insns      mem_bytes      const_term_cpu      lin_term_cpu        const_term_mem      lin_term_mem        
        WasmInsnExec             246            None           1476           0              6                   0                   0                   0                   
        WasmMemAlloc             184            None           0              184            0                   0                   1                   0                   
        HostMemAlloc             1              Some(152)      1142           168            1141                1                   16                  128                 
        HostMemCpy               1              Some(65)       51             0              39                  24                  0                   0                   
        HostMemCmp               1              Some(74)       57             0              20                  64                  0                   0                   
        DispatchHostFunction     176            None           46288          0              263                 0                   0                   0                   
        VisitObject              97             None           10476          0              108                 0                   0                   0                   
        ValSer                   1              Some(49)       617            165            591                 69                  18                  384                 
        ValDeser                 1              Some(103)      1139           119            1112                34                  16                  128                 
        ComputeSha256Hash        1              Some(193)      9179           40             2924                4149                40                  0                   
        ComputeEd25519PubKey     226            None           5781984        0              25584               0                   0                   0                   
        MapEntry                 250            None           13250          0              53                  0                   0                   0                   
        VecEntry                 186            None           0              0              0                   0                   0                   0                   
        VerifyEd25519Sig         1              Some(227)      381748         0              376877              2747                0                   0                   
        VmMemRead                1              Some(69)       194            0              182                 24                  0                   0                   
        VmMemWrite               1              Some(160)      212            0              182                 24                  0                   0                   
        VmInstantiation          1              Some(147)      1047534        136937         967154              69991               131103              5080                
        VmCachedInstantiation    1              Some(147)      1047534        136937         967154              69991               131103              5080                
        InvokeVmFunction         47             None           52875          658            1125                0                   14                  0                   
        ComputeKeccak256Hash     1              Some(1)        2917           40             2890                3561                40                  0                   
        ComputeEcdsaSecp256k1Key 1              None           38363          0              38363               0                   0                   0                   
        ComputeEcdsaSecp256k1Sig 1              None           224            0              224                 0                   0                   0                   
        RecoverEcdsaSecp256k1Key 1              None           1666155        201            1666155             0                   201                 0                   
        Int256AddSub             1              None           1716           119            1716                0                   119                 0                   
        Int256Mul                1              None           2226           119            2226                0                   119                 0                   
        Int256Div                1              None           2333           119            2333                0                   119                 0                   
        Int256Pow                1              None           5212           119            5212                0                   119                 0                   
        Int256Shift              1              None           412            119            412                 0                   119                 0                   
        =====================================================================================================================================================================
        Total # times meter was called: 28

    "#]]
    .assert_eq(&actual);
    Ok(())
}
