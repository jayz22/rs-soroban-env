use crate::{
    num::{i256_into_parts, u256_into_parts},
    Host, HostError, I256Object, I256Small, I256Val, U256Object, U256Small, U256Val, I256, U256,
};

#[macro_export]
macro_rules! impl_wrapping_obj_from_num {
    ($host_fn: ident, $hot: ty, $num: ty) => {
        fn $host_fn(
            &self,
            _vmcaller: &mut VmCaller<Host>,
            u: $num,
        ) -> Result<<$hot as HostObjectType>::Wrapper, HostError> {
            self.add_host_object(<$hot>::from(u))
        }
    };
}

#[macro_export]
macro_rules! impl_wrapping_obj_to_num {
    ($host_fn: ident, $data: ty, $num: ty) => {
        fn $host_fn(
            &self,
            _vmcaller: &mut VmCaller<Host>,
            obj: <$data as HostObjectType>::Wrapper,
        ) -> Result<$num, HostError> {
            self.visit_obj(obj, |t: &$data| Ok(t.clone().into()))
        }
    };
}

#[macro_export]
macro_rules! impl_bignum_host_fns {
    ($host_fn: ident, $method: ident, $num: ty, $valty: ty, $cost: ident) => {
        fn $host_fn(
            &self,
            vmcaller: &mut VmCaller<Self::VmUserState>,
            lhs_val: $valty,
            rhs_val: $valty,
        ) -> Result<$valty, Self::Error> {
            use soroban_env_common::TryIntoVal;
            self.charge_budget(ContractCostType::$cost, None)?;
            let lhs: $num = lhs_val.to_val().try_into_val(self)?;
            let rhs: $num = rhs_val.to_val().try_into_val(self)?;
            let res: $num = lhs.$method(rhs).ok_or_else(|| {
                self.err(
                    ScErrorType::Object,
                    ScErrorCode::ArithDomain,
                    "overflow has occured",
                    &[lhs_val.to_val(), rhs_val.to_val()],
                )
            })?;
            Ok(res.try_into_val(self)?)
        }
    };
}

#[macro_export]
macro_rules! impl_bignum_host_fns_rhs_u32 {
    ($host_fn: ident, $method: ident, $num: ty, $valty: ty, $cost: ident) => {
        fn $host_fn(
            &self,
            vmcaller: &mut VmCaller<Self::VmUserState>,
            lhs_val: $valty,
            rhs_val: U32Val,
        ) -> Result<$valty, Self::Error> {
            use soroban_env_common::TryIntoVal;
            self.charge_budget(ContractCostType::$cost, None)?;
            let lhs: $num = lhs_val.to_val().try_into_val(self)?;
            let res = lhs.$method(rhs_val.into()).ok_or_else(|| {
                self.err(
                    ScErrorType::Object,
                    ScErrorCode::ArithDomain,
                    "overflow has occured",
                    &[lhs_val.to_val(), rhs_val.to_val()],
                )
            })?;
            Ok(res.try_into_val(self)?)
        }
    };
}

impl Host {
    pub(crate) fn u256_val_to_parts(
        &self,
        val: U256Val,
    ) -> Result<(u64, u64, u64, u64), HostError> {
        if let Ok(so) = U256Small::try_from(val) {
            Ok(u256_into_parts(U256::from(so)))
        } else {
            let obj = U256Object::try_from(val)?;
            self.visit_obj(obj, move |u: &U256| Ok(u256_into_parts(*u)))
        }
    }

    pub(crate) fn i256_val_to_parts(
        &self,
        val: I256Val,
    ) -> Result<(i64, u64, u64, u64), HostError> {
        if let Ok(so) = I256Small::try_from(val) {
            Ok(i256_into_parts(I256::from(so)))
        } else {
            let obj = I256Object::try_from(val)?;
            self.visit_obj(obj, move |i: &I256| Ok(i256_into_parts(*i)))
        }
    }
}
