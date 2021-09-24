use crate::Evm;

use ethers::{
    abi::{Detokenize, Function, Tokenize},
    prelude::{decode_function_data, encode_function_data},
    types::{Address, Bytes, U256},
};

use evmodin::{tracing::Tracer, AnalyzedCode, CallKind, Host, Message, Revision, StatusCode};

use eyre::Result;

// TODO: Check if we can implement this as the base layer of an ethers-provider
// Middleware stack instead of doing RPC calls.
pub struct EvmOdin<S, T> {
    pub host: S,
    pub gas_limit: u64,
    pub call_kind: Option<CallKind>,
    pub revision: Revision,
    pub tracer: T,
}

impl<S: Host, T: Tracer> EvmOdin<S, T> {
    /// Given a gas limit, vm revision, and initialized host state
    pub fn new(host: S, gas_limit: u64, revision: Revision, tracer: T) -> Self {
        Self { host, gas_limit, revision, tracer, call_kind: None }
    }
}

/// Helper trait for exposing additional functionality over EVMOdin Hosts
pub trait HostExt: Host {
    /// Gets the bytecode at the specified address. `None` if the specified address
    /// is not a contract account.
    fn get_code(&self, address: &Address) -> Option<&bytes::Bytes>;
    /// Sets the bytecode at the specified address to the provided value.
    fn set_code(&mut self, address: Address, code: bytes::Bytes);
}

impl<S: HostExt, Tr: Tracer> Evm<S> for EvmOdin<S, Tr> {
    type ReturnReason = StatusCode;

    fn reset(&mut self, state: S) {
        self.host = state;
    }

    fn initialize_contracts<I: IntoIterator<Item = (Address, Bytes)>>(&mut self, contracts: I) {
        contracts.into_iter().for_each(|(address, bytecode)| {
            self.host.set_code(address, bytecode.0);
        })
    }

    fn init_state(&self) -> &S {
        &self.host
    }

    fn check_success(
        &mut self,
        address: Address,
        result: Self::ReturnReason,
        should_fail: bool,
    ) -> bool {
        if should_fail {
            match result {
                // If the function call reverted, we're good.
                StatusCode::Revert => true,
                // If the function call was successful in an expected fail case,
                // we make a call to the `failed()` function inherited from DS-Test
                StatusCode::Success => self.failed(address).unwrap_or(false),
                err => {
                    tracing::error!(?err);
                    false
                }
            }
        } else {
            matches!(result, StatusCode::Success)
        }
    }

    /// Runs the selected function
    fn call<D: Detokenize, T: Tokenize>(
        &mut self,
        from: Address,
        to: Address,
        func: &Function,
        args: T, // derive arbitrary for Tokenize?
        value: U256,
    ) -> Result<(D, Self::ReturnReason, u64)> {
        let calldata = encode_function_data(func, args)?;

        // For the `func.constant` field usage
        #[allow(deprecated)]
        let message = Message {
            sender: from,
            destination: to,
            // What should this be?
            depth: 0,
            kind: self.call_kind.unwrap_or(CallKind::Call),
            input_data: calldata.0,
            value,
            gas: self.gas_limit as i64,
            is_static: func.constant
                || matches!(
                    func.state_mutability,
                    ethers::abi::StateMutability::View | ethers::abi::StateMutability::Pure
                ),
        };

        // get the bytecode at the host
        let bytecode = self.host.get_code(&to).ok_or_else(|| {
            eyre::eyre!("there should be a smart contract at the destination address")
        })?;
        let bytecode = AnalyzedCode::analyze(bytecode.as_ref());
        let output =
            bytecode.execute(&mut self.host, &mut self.tracer, None, message, self.revision);

        // let gas = dapp_utils::remove_extra_costs(gas_before - gas_after, calldata.as_ref());

        let retdata = decode_function_data(func, output.output_data, false)?;

        // TODO: Figure out gas accounting.
        let gas = U256::from(0);

        Ok((retdata, output.status_code, gas.as_u64()))
    }
}

#[cfg(any(test, feature = "evmodin-helpers"))]
mod helpers {
    use super::*;
    use ethers::utils::keccak256;
    use evmodin::util::mocked_host::{Account, MockedHost};
    impl HostExt for MockedHost {
        fn get_code(&self, address: &Address) -> Option<&bytes::Bytes> {
            self.accounts.get(address).map(|acc| &acc.code)
        }

        fn set_code(&mut self, address: Address, bytecode: bytes::Bytes) {
            let hash = keccak256(&bytecode);
            self.accounts.insert(
                address,
                Account {
                    nonce: 0,
                    balance: 0.into(),
                    code: bytecode,
                    code_hash: hash.into(),
                    storage: Default::default(),
                },
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{can_call_vm_directly, solidity_unit_test, COMPILED};
    use evmodin::{tracing::NoopTracer, util::mocked_host::MockedHost};

    #[test]
    fn evmodin_can_call_vm_directly() {
        let revision = Revision::Istanbul;
        let compiled = COMPILED.get("Greeter").expect("could not find contract");

        let host = MockedHost::default();
        let addr: Address = "0x1000000000000000000000000000000000000000".parse().unwrap();

        let gas_limit = 12_000_000;
        let evm = EvmOdin::new(host, gas_limit, revision, NoopTracer);

        can_call_vm_directly(evm, addr, compiled);
    }

    #[test]
    // TODO: This fails because the cross-contract host does not work.
    #[ignore]
    fn evmodin_can_call_solidity_unit_test() {
        let revision = Revision::Istanbul;
        let compiled = COMPILED.get("Greeter").expect("could not find contract");
        let addr: Address = "0x1000000000000000000000000000000000000000".parse().unwrap();
        let host = MockedHost::default();
        let gas_limit = 12_000_000;
        let evm = EvmOdin::new(host, gas_limit, revision, NoopTracer);

        solidity_unit_test(evm, addr, compiled);
    }
}
