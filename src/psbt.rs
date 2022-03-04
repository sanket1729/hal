use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use bitcoin::util::{bip32, psbt};
use bitcoin::Network;
use bitcoin;
use bitcoin::util::psbt::PsbtSigHashType;

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct PsbtGlobalInfo {
	pub unsigned_tx: ::tx::TransactionInfo,
}

impl ::GetInfo<PsbtGlobalInfo> for psbt::PartiallySignedTransaction {
	fn get_info(&self, network: Network) -> PsbtGlobalInfo {
		PsbtGlobalInfo {
			unsigned_tx: self.unsigned_tx.get_info(network),
		}
	}
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct HDPathInfo {
	pub master_fingerprint: bip32::Fingerprint,
	pub path: bip32::DerivationPath,
}

pub fn sighashtype_to_string(sht: PsbtSigHashType) -> String {
	if let Ok(sht) = sht.ecdsa_hash_ty() {
		use bitcoin::EcdsaSigHashType::*;
		match sht {
			All => "ALL",
			None => "NONE",
			Single => "SINGLE",
			AllPlusAnyoneCanPay => "ALL|ANYONECANPAY",
			NonePlusAnyoneCanPay => "NONE|ANYONECANPAY",
			SinglePlusAnyoneCanPay => "SINGLE|ANYONECANPAY",
		}.to_owned()
	} else if let Ok(sht) = sht.schnorr_hash_ty() {
		use bitcoin::SchnorrSigHashType::*;
		match sht {
			Default => "DEFAULT",
			All => "ALL",
			None => "NONE",
			Single => "SINGLE",
			AllPlusAnyoneCanPay => "ALL|ANYONECANPAY",
			NonePlusAnyoneCanPay => "NONE|ANYONECANPAY",
			SinglePlusAnyoneCanPay => "SINGLE|ANYONECANPAY",
    		Reserved => panic!("unreachable!"),
		}.to_owned()
	} else {
		panic!("Non-standard sighash type")
	}
}

pub fn sighashtype_values() -> &'static [&'static str] {
	&[ "DEFAULT", "ALL", "NONE", "SINGLE", "ALL|ANYONECANPAY", "NONE|ANYONECANPAY", "SINGLE|ANYONECANPAY"]
}

pub fn sighashtype_from_string(sht: &str) -> PsbtSigHashType {
	use bitcoin::SchnorrSigHashType::*;
	let schnorr_hash_ty = match sht {
		"DEFAULT" => Default,
		"ALL" => All,
		"NONE" => None,
		"SINGLE" => Single,
		"ALL|ANYONECANPAY" => AllPlusAnyoneCanPay,
		"NONE|ANYONECANPAY" => NonePlusAnyoneCanPay,
		"SINGLE|ANYONECANPAY" => SinglePlusAnyoneCanPay,
		_ => panic!("invalid SIGHASH type value -- possible values: {:?}", &sighashtype_values()),
	};
	PsbtSigHashType::from(schnorr_hash_ty)
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct PsbtInputInfo {
	#[serde(skip_serializing_if = "Option::is_none")]
	pub non_witness_utxo: Option<::tx::TransactionInfo>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub witness_utxo: Option<::tx::OutputInfo>,
	#[serde(skip_serializing_if = "HashMap::is_empty")]
	pub partial_sigs: HashMap<::HexBytes, ::HexBytes>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub sighash_type: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub redeem_script: Option<::tx::OutputScriptInfo>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub witness_script: Option<::tx::OutputScriptInfo>,
	#[serde(skip_serializing_if = "HashMap::is_empty")]
	pub hd_keypaths: HashMap<::HexBytes, HDPathInfo>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub final_script_sig: Option<::tx::InputScriptInfo>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub final_script_witness: Option<Vec<::HexBytes>>,
	#[serde(skip_serializing_if = "HashMap::is_empty")]
	pub tap_scripts: HashMap<::HexBytes, ::HexBytes>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub tap_internal_key: Option<::HexBytes>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub tap_merkle_root: Option<::HexBytes>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub tap_internal_key_sig: Option<::HexBytes>,
	#[serde(skip_serializing_if = "HashMap::is_empty")]
	pub tap_script_sigs: HashMap<::HexBytes, ::HexBytes>,
}

impl ::GetInfo<PsbtInputInfo> for psbt::Input {
	fn get_info(&self, network: Network) -> PsbtInputInfo {
		PsbtInputInfo {
			non_witness_utxo: self.non_witness_utxo.as_ref().map(|u| u.get_info(network)),
			witness_utxo: self.witness_utxo.as_ref().map(|u| u.get_info(network)),
			partial_sigs: {
				let mut partial_sigs = HashMap::new();
				for (key, value) in self.partial_sigs.iter() {
					partial_sigs.insert(key.to_bytes().into(), value.to_vec().into());
				}
				partial_sigs
			},
			sighash_type: self.sighash_type.map(sighashtype_to_string),
			redeem_script: self.redeem_script.as_ref()
				.map(|s| ::tx::OutputScript(s).get_info(network)),
			witness_script: self.witness_script.as_ref()
				.map(|s| ::tx::OutputScript(s).get_info(network)),
			hd_keypaths: {
				let mut hd_keypaths = HashMap::new();
				for (key, value) in self.bip32_derivation.iter() {
					hd_keypaths.insert(bitcoin::PublicKey::new(*key).to_bytes().into(),
						HDPathInfo {
							master_fingerprint: value.0[..].into(),
							path: value.1.clone(),
						},
					);
				}
				hd_keypaths
			},
			final_script_sig: self.final_script_sig.as_ref()
				.map(|s| ::tx::InputScript(s).get_info(network)),
			final_script_witness: self.final_script_witness.as_ref()
				.map(|w| w.iter().map(|p| p.clone().into()).collect()),
			tap_scripts: {
				let mut sigs = HashMap::new();
				for (key, value) in self.tap_scripts.iter() {
					let mut psbt_value = value.0.as_bytes().to_vec();
					psbt_value.push(value.1.to_consensus());
					sigs.insert(key.serialize().into(), psbt_value.into());
				}
				sigs
			},
			tap_internal_key: self.tap_internal_key.map(|x| x.serialize().to_vec().into()),
			tap_merkle_root: self.tap_merkle_root.map(|x| x.to_vec().into()),
			tap_internal_key_sig: self.tap_key_sig.map(|x| x.to_vec().into()),
			tap_script_sigs: {
				let mut sigs = HashMap::new();
				for (key, value) in self.tap_script_sigs.iter() {
					let mut psbt_key = key.0.serialize().to_vec();
					psbt_key.extend(key.1.iter());
					sigs.insert(psbt_key.into(), value.to_vec().into());
				}
				sigs
			},
		}
	}
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct PsbtOutputInfo {
	#[serde(skip_serializing_if = "Option::is_none")]
	pub redeem_script: Option<::tx::OutputScriptInfo>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub witness_script: Option<::tx::OutputScriptInfo>,
	#[serde(skip_serializing_if = "HashMap::is_empty")]
	pub hd_keypaths: HashMap<::HexBytes, HDPathInfo>,
}

impl ::GetInfo<PsbtOutputInfo> for psbt::Output {
	fn get_info(&self, network: Network) -> PsbtOutputInfo {
		PsbtOutputInfo {
			redeem_script: self.redeem_script.as_ref()
				.map(|s| ::tx::OutputScript(s).get_info(network)),
			witness_script: self.witness_script.as_ref()
				.map(|s| ::tx::OutputScript(s).get_info(network)),
			hd_keypaths: {
				let mut hd_keypaths = HashMap::new();
				for (key, value) in self.bip32_derivation.iter() {
					hd_keypaths.insert(bitcoin::PublicKey::new(*key).to_bytes().into(),
						HDPathInfo {
							master_fingerprint: value.0[..].into(),
							path: value.1.clone(),
						},
					);
				}
				hd_keypaths
			},
		}
	}
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct PsbtInfo {
	pub global: PsbtGlobalInfo,
	pub inputs: Vec<PsbtInputInfo>,
	pub outputs: Vec<PsbtOutputInfo>,
}

impl ::GetInfo<PsbtInfo> for psbt::PartiallySignedTransaction {
	fn get_info(&self, network: Network) -> PsbtInfo {
		PsbtInfo {
			global: self.get_info(network),
			inputs: self.inputs.iter().map(|i| i.get_info(network)).collect(),
			outputs: self.outputs.iter().map(|o| o.get_info(network)).collect(),
		}
	}
}
