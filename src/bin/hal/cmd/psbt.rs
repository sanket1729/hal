use std::fs::File;
use std::io::{Read, Write};
use std::str::FromStr;

use base64;
use clap;
use hal::bitcoin::hashes::Hash;
use hal::bitcoin::schnorr::TapTweak;
use hal::bitcoin::util::taproot::{TapLeafHash, LeafVersion};
use hal::psbt::PsbtInfo;
use hex;

use bitcoin::{PrivateKey, consensus::{deserialize, serialize}};
use bitcoin::secp256k1;
use bitcoin::util::bip32;
use bitcoin::util::psbt;
use bitcoin::{self, PublicKey, Transaction};
use bitcoin::XOnlyPublicKey;

use cmd;
use miniscript::{DescriptorTrait, Miniscript, Tap, DescriptorPublicKey, Descriptor, ToPublicKey};

pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand_group("psbt", "partially signed Bitcoin transactions")
		.subcommand(cmd_create())
		.subcommand(cmd_decode())
		.subcommand(cmd_edit())
		.subcommand(cmd_finalize())
		.subcommand(cmd_merge())
		.subcommand(cmd_rawsign())
		.subcommand(cmd_utxoupdate())
}

pub fn execute<'a>(matches: &clap::ArgMatches<'a>) {
	match matches.subcommand() {
		("create", Some(ref m)) => exec_create(&m),
		("decode", Some(ref m)) => exec_decode(&m),
		("edit", Some(ref m)) => exec_edit(&m),
		("finalize", Some(ref m)) => exec_finalize(&m),
		("merge", Some(ref m)) => exec_merge(&m),
		("rawsign", Some(ref m)) => exec_rawsign(&m),
		("utxoupdate", Some(ref m)) => exec_utxoupdate(&m),
		(c, _) => eprintln!("command {} unknown", c),
	};
}

#[derive(Debug)]
enum PsbtSource {
	Base64,
	Hex,
	File,
}

/// Tries to decode the string as hex and base64, if it works, returns the bytes.
/// If not, tries to open a filename with the given string as relative path, if it works, returns
/// the content bytes.
/// Also returns an enum value indicating which source worked.
fn file_or_raw(flag: &str) -> (Vec<u8>, PsbtSource) {
	if let Ok(raw) = hex::decode(&flag) {
		(raw, PsbtSource::Hex)
	} else if let Ok(raw) = base64::decode(&flag) {
		(raw, PsbtSource::Base64)
	} else if let Ok(mut file) = File::open(&flag) {
		let mut buf = Vec::new();
		file.read_to_end(&mut buf).expect("error reading file");
		(buf, PsbtSource::File)
	} else {
		panic!("Can't load PSBT: invalid hex, base64 or unknown file");
	}
}

fn cmd_create<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("create", "create a PSBT from an unsigned raw transaction").args(&[
		cmd::arg("raw-tx", "the raw transaction in hex").required(true),
		cmd::opt("output", "where to save the merged PSBT output")
			.short("o")
			.takes_value(true)
			.required(false),
		cmd::opt("raw-stdout", "output the raw bytes of the result to stdout")
			.short("r")
			.required(false),
	])
}

fn exec_create<'a>(matches: &clap::ArgMatches<'a>) {
	let hex_tx = matches.value_of("raw-tx").expect("no raw tx provided");
	let raw_tx = hex::decode(hex_tx).expect("could not decode raw tx");
	let tx: Transaction = deserialize(&raw_tx).expect("invalid tx format");

	let psbt = psbt::PartiallySignedTransaction::from_unsigned_tx(tx)
		.expect("couldn't create a PSBT from the transaction");

	let serialized = serialize(&psbt);
	if let Some(path) = matches.value_of("output") {
		let mut file = File::create(&path).expect("failed to open output file");
		file.write_all(&serialized).expect("error writing output file");
	} else if matches.is_present("raw-stdout") {
		::std::io::stdout().write_all(&serialized).unwrap();
	} else {
		print!("{}", base64::encode(&serialized));
	}
}

fn cmd_decode<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("decode", "decode a PSBT to JSON").args(&cmd::opts_networks()).args(&[
		cmd::opt_yaml(),
		cmd::arg("psbt", "the PSBT file or raw PSBT in base64/hex").required(true),
	])
}

fn exec_decode<'a>(matches: &clap::ArgMatches<'a>) {
	let (raw_psbt, _) = file_or_raw(matches.value_of("psbt").unwrap());

	let psbt: psbt::PartiallySignedTransaction = deserialize(&raw_psbt).expect("invalid PSBT");

	let info : PsbtInfo = hal::GetInfo::get_info(&psbt, cmd::network(matches));
	cmd::print_output(matches, &info)
}

fn cmd_edit<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("edit", "edit a PSBT").args(&[
		cmd::arg("psbt", "PSBT to edit, either base64/hex or a file path").required(true),
		cmd::opt("input-idx", "the input index to edit")
			.display_order(1)
			.takes_value(true)
			.required(false),
		cmd::opt("output-idx", "the output index to edit")
			.display_order(2)
			.takes_value(true)
			.required(false),
		cmd::opt("output", "where to save the resulting PSBT file -- in place if omitted")
			.short("o")
			.display_order(3)
			.next_line_help(true)
			.takes_value(true)
			.required(false),
		cmd::opt("raw-stdout", "output the raw bytes of the result to stdout")
			.short("r")
			.required(false),
		//
		// values used in both inputs and outputs
		cmd::opt("redeem-script", "the redeem script")
			.display_order(99)
			.next_line_help(true)
			.takes_value(true)
			.required(false),
		cmd::opt("witness-script", "the witness script")
			.display_order(99)
			.next_line_help(true)
			.takes_value(true)
			.required(false),
		cmd::opt("hd-keypaths", "the HD wallet keypaths `<pubkey>:<master-fp>:<path>,...`")
			.display_order(99)
			.next_line_help(true)
			.takes_value(true)
			.required(false),
		cmd::opt("hd-keypaths-add", "add an HD wallet keypath `<pubkey>:<master-fp>:<path>`")
			.display_order(99)
			.next_line_help(true)
			.takes_value(true)
			.required(false),
		//
		// input values
		cmd::opt("non-witness-utxo", "the non-witness UTXO field in hex (full transaction)")
			.display_order(99)
			.next_line_help(true)
			.takes_value(true)
			.required(false),
		cmd::opt("witness-utxo", "the witness UTXO field in hex (only output)")
			.display_order(99)
			.next_line_help(true)
			.takes_value(true)
			.required(false),
		cmd::opt("partial-sigs", "set partial sigs `<pubkey>:<signature>,...`")
			.display_order(99)
			.next_line_help(true)
			.takes_value(true)
			.required(false),
		cmd::opt("partial-sigs-add", "add a partial sig pair `<pubkey>:<signature>`")
			.display_order(99)
			.next_line_help(true)
			.takes_value(true)
			.required(false),
		cmd::opt("sighash-type", "the sighash type")
			.display_order(99)
			.next_line_help(true)
			.takes_value(true)
			.required(false),
		cmd::opt("sha256-preimages-add", "add a sha256 preimage `<preimage>:<sha256>`")
			.display_order(99)
			.next_line_help(true)
			.takes_value(true)
			.required(false),
		// (omitted) redeem-script
		// (omitted) witness-script
		// (omitted) hd-keypaths
		// (omitted) hd-keypaths-add
		cmd::opt("final-script-sig", "set final script signature")
			.display_order(99)
			.next_line_help(true)
			.takes_value(true)
			.required(false),
		cmd::opt("final-script-witness", "set final script witness as comma-separated hex values")
			.display_order(99)
			.next_line_help(true)
			.takes_value(true)
			.required(false),
		//
		// output values
		// (omitted) redeem-script
		// (omitted) witness-script
		// (omitted) hd-keypaths
		// (omitted) hd-keypaths-add
	])
}

/// Parses a `<pubkey>:<signature>` pair.
fn parse_partial_sig_pair(pair_str: &str) -> (PublicKey, bitcoin::EcdsaSig) {
	let mut pair = pair_str.splitn(2, ":");
	let pubkey = pair.next().unwrap().parse().expect("invalid partial sig pubkey");
	let sig = {
		let hex = pair.next().expect("invalid partial sig pair: missing signature");
		hex::decode(&hex).expect("invalid partial sig signature hex")
	};
	(pubkey, bitcoin::EcdsaSig::from_slice(&sig).expect("Invalid Ecdsa sig"))
}

fn parse_hash_preimage_pair(pair_str: &str) -> (Vec<u8>, bitcoin::hashes::sha256::Hash) {
	let mut pair = pair_str.splitn(2, ":");
	let preimage  = {
		let hex = pair.next().expect("Invalid sha256 hex");
		hex::decode(&hex).expect("Unreachable!")
	};
	let hash = {
		let hex = pair.next().expect("Invalid sha256 hex");
		let sl = hex::decode(&hex).expect("Unreachable!");
		bitcoin::hashes::sha256::Hash::from_slice(&sl).unwrap()
	};
	(preimage, hash)
}

fn parse_hd_keypath_triplet(
	triplet_str: &str,
) -> (bitcoin::secp256k1::PublicKey, (bip32::Fingerprint, bip32::DerivationPath)) {
	let mut triplet = triplet_str.splitn(3, ":");
	let pubkey = triplet.next().unwrap().parse().expect("invalid HD keypath pubkey");
	let fp = {
		let hex = triplet.next().expect("invalid HD keypath triplet: missing fingerprint");
		let raw = hex::decode(&hex).expect("invalid HD keypath fingerprint hex");
		if raw.len() != 4 {
			panic!("invalid HD keypath fingerprint size: {} instead of 4", raw.len());
		}
		raw[..].into()
	};
	let path = triplet
		.next()
		.expect("invalid HD keypath triplet: missing HD path")
		.parse()
		.expect("invalid derivation path format");
	(pubkey, (fp, path))
}

fn edit_input<'a>(
	idx: usize,
	matches: &clap::ArgMatches<'a>,
	psbt: &mut psbt::PartiallySignedTransaction,
) {
	let input = psbt.inputs.get_mut(idx).expect("input index out of range");

	if let Some(hex) = matches.value_of("non-witness-utxo") {
		let raw = hex::decode(&hex).expect("invalid non-witness-utxo hex");
		let utxo = deserialize(&raw).expect("invalid non-witness-utxo transaction");
		input.non_witness_utxo = Some(utxo);
	}

	if let Some(hex) = matches.value_of("witness-utxo") {
		let raw = hex::decode(&hex).expect("invalid witness-utxo hex");
		let utxo = deserialize(&raw).expect("invalid witness-utxo transaction");
		input.witness_utxo = Some(utxo);
	}

	if let Some(csv) = matches.value_of("partial-sigs") {
		input.partial_sigs = csv.split(",").map(parse_partial_sig_pair).collect();
	}
	if let Some(pairs) = matches.values_of("partial-sigs-add") {
		for (pk, sig) in pairs.map(parse_partial_sig_pair) {
			if input.partial_sigs.insert(pk, sig).is_some() {
				panic!("public key {} is already in partial sigs", &pk);
			}
		}
	}

	if let Some(pairs) = matches.values_of("sha256-preimages-add") {
		for (preimage, hash) in pairs.map(parse_hash_preimage_pair) {
			if input.sha256_preimages.insert(hash, preimage.to_vec()).is_some() {
				panic!("sha256 Hash {} is already in partial preimages", &hash);
			}
		}
	}

	if let Some(sht) = matches.value_of("sighash-type") {
		input.sighash_type = Some(hal::psbt::sighashtype_from_string(&sht));
	}

	if let Some(hex) = matches.value_of("redeem-script") {
		let raw = hex::decode(&hex).expect("invalid redeem-script hex");
		input.redeem_script = Some(raw.into());
	}

	if let Some(hex) = matches.value_of("witness-script") {
		let raw = hex::decode(&hex).expect("invalid witness-script hex");
		input.witness_script = Some(raw.into());
	}

	if let Some(csv) = matches.value_of("hd-keypaths") {
		input.bip32_derivation = csv.split(",").map(parse_hd_keypath_triplet).collect();
	}
	if let Some(triplets) = matches.values_of("hd-keypaths-add") {
		for (pk, pair) in triplets.map(parse_hd_keypath_triplet) {
			if input.bip32_derivation.insert(pk, pair).is_some() {
				panic!("public key {} is already in HD keypaths", &pk);
			}
		}
	}

	if let Some(hex) = matches.value_of("final-script-sig") {
		let raw = hex::decode(&hex).expect("invalid final-script-sig hex");
		input.final_script_sig = Some(raw.into());
	}

	if let Some(csv) = matches.value_of("final-script-witness") {
		let vhex = csv.split(",");
		let vraw = vhex.map(|h| hex::decode(&h).expect("invalid final-script-witness hex"));
		input.final_script_witness = Some(bitcoin::Witness::from_vec(vraw.collect()));
	}
}

fn edit_output<'a>(
	idx: usize,
	matches: &clap::ArgMatches<'a>,
	psbt: &mut psbt::PartiallySignedTransaction,
) {
	let output = psbt.outputs.get_mut(idx).expect("output index out of range");

	if let Some(hex) = matches.value_of("redeem-script") {
		let raw = hex::decode(&hex).expect("invalid redeem-script hex");
		output.redeem_script = Some(raw.into());
	}

	if let Some(hex) = matches.value_of("witness-script") {
		let raw = hex::decode(&hex).expect("invalid witness-script hex");
		output.witness_script = Some(raw.into());
	}

	if let Some(csv) = matches.value_of("hd-keypaths") {
		output.bip32_derivation = csv.split(",").map(parse_hd_keypath_triplet).collect();
	}
	if let Some(triplets) = matches.values_of("hd-keypaths-add") {
		for (pk, pair) in triplets.map(parse_hd_keypath_triplet) {
			if output.bip32_derivation.insert(pk, pair).is_some() {
				panic!("public key {} is already in HD keypaths", &pk);
			}
		}
	}
}

fn exec_edit<'a>(matches: &clap::ArgMatches<'a>) {
	let (raw, source) = file_or_raw(&matches.value_of("psbt").unwrap());
	let mut psbt: psbt::PartiallySignedTransaction =
		deserialize(&raw).expect("invalid PSBT format");

	match (matches.value_of("input-idx"), matches.value_of("output-idx")) {
		(None, None) => panic!("no input or output index provided"),
		(Some(_), Some(_)) => panic!("can only edit an input or an output at a time"),
		(Some(idx), _) => {
			edit_input(idx.parse().expect("invalid input index"), &matches, &mut psbt)
		}
		(_, Some(idx)) => {
			edit_output(idx.parse().expect("invalid output index"), &matches, &mut psbt)
		}
	}

	let edited_raw = serialize(&psbt);
	if let Some(path) = matches.value_of("output") {
		let mut file = File::create(&path).expect("failed to open output file");
		file.write_all(&edited_raw).expect("error writing output file");
	} else if matches.is_present("raw-stdout") {
		::std::io::stdout().write_all(&edited_raw).unwrap();
	} else {
		match source {
			PsbtSource::Hex => print!("{}", hex::encode(&edited_raw)),
			PsbtSource::Base64 => print!("{}", base64::encode(&edited_raw)),
			PsbtSource::File => {
				let path = matches.value_of("psbt").unwrap();
				let mut file = File::create(&path).expect("failed to PSBT file for writing");
				file.write_all(&edited_raw).expect("error writing PSBT file");
			}
		}
	}
}

fn cmd_finalize<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("finalize", "finalize a PSBT and print the fully signed tx in hex").args(&[
		cmd::arg("psbt", "PSBT to finalize, either base64/hex or a file path").required(true),
		cmd::opt("raw-stdout", "output the raw bytes of the result to stdout")
			.short("r")
			.required(false),
	])
}

fn exec_finalize<'a>(matches: &clap::ArgMatches<'a>) {
	let (raw, _) = file_or_raw(&matches.value_of("psbt").unwrap());
	let mut psbt: psbt::PartiallySignedTransaction = deserialize(&raw).expect("invalid PSBT format");


	// Create a secp context, should there be one with static lifetime?
	let secp = secp256k1::Secp256k1::verification_only();
	::miniscript::psbt::finalize(&mut psbt, &secp).expect("failed to finalize");

	let finalized_raw = serialize(&psbt.extract_tx());
	if matches.is_present("raw-stdout") {
		::std::io::stdout().write_all(&finalized_raw).unwrap();
	} else {
		print!("{}", ::hex::encode(&finalized_raw));
	}
}

fn cmd_merge<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("merge", "merge multiple PSBT files into one").args(&[
		cmd::arg("psbts", "PSBTs to merge; can be file paths or base64/hex")
			.multiple(true)
			.required(true),
		cmd::opt("output", "where to save the merged PSBT output")
			.short("o")
			.takes_value(true)
			.required(false),
		cmd::opt("raw-stdout", "output the raw bytes of the result to stdout")
			.short("r")
			.required(false),
	])
}

fn exec_merge<'a>(matches: &clap::ArgMatches<'a>) {
	let mut parts = matches.values_of("psbts").unwrap().map(|f| {
		let (raw, _) = file_or_raw(&f);
		let psbt: psbt::PartiallySignedTransaction =
			deserialize(&raw).expect("invalid PSBT format");
		psbt
	});

	let mut merged = parts.next().unwrap();
	for (idx, part) in parts.enumerate() {
		if part.unsigned_tx != merged.unsigned_tx {
			panic!("PSBTs are not compatible");
		}

		merged.combine(part).expect(&format!("error merging PSBT #{}", idx));
	}

	let merged_raw = serialize(&merged);
	if let Some(path) = matches.value_of("output") {
		let mut file = File::create(&path).expect("failed to open output file");
		file.write_all(&merged_raw).expect("error writing output file");
	} else if matches.is_present("raw-stdout") {
		::std::io::stdout().write_all(&merged_raw).unwrap();
	} else {
		print!("{}", base64::encode(&merged_raw));
	}
}

fn cmd_rawsign<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("rawsign", "sign a psbt with private key and add sig to partial sigs").args(&[
		cmd::arg("psbt", "PSBT to finalize, either base64/hex or a file path").required(true),
		cmd::arg("input-idx", "the input index to edit").required(true),
		cmd::arg("priv-key", "the private key in WIF/hex").required(true),
		cmd::arg("compressed", "Whether the corresponding pk is compressed")
			.required(false)
			.default_value("true"),
		cmd::opt("raw-stdout", "output the raw bytes of the result to stdout")
			.short("r")
			.required(false),
		cmd::opt("output", "where to save the resulting PSBT file -- in place if omitted")
			.short("o")
			.takes_value(true)
			.required(false),
	])
}

fn cmd_utxoupdate<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("utxoupdate", "Update a psbt with descriptor information. Updates the \
	witness script/redeem script/control block information based on spend type").args(&[
		cmd::arg("psbt", "PSBT to finalize, either base64/hex or a file path").required(true),
		cmd::arg("input-idx", "the input index to edit").required(true),
		cmd::arg("desc", "The descriptors with only public information").required(true),
		cmd::opt("raw-stdout", "output the raw bytes of the result to stdout")
			.short("r")
			.required(false),
		cmd::opt("output", "where to save the resulting PSBT file -- in place if omitted")
			.short("o")
			.takes_value(true)
			.required(false),
	])
}

fn exec_utxoupdate<'a>(matches: &clap::ArgMatches<'a>) {
	let (raw, source) = file_or_raw(&matches.value_of("psbt").unwrap());
	let mut psbt: psbt::PartiallySignedTransaction = deserialize(&raw).expect("invalid PSBT format");

	let desc = matches.value_of("desc").expect("No descriptor provided");
	let i = matches.value_of("input-idx").expect("Input index not provided")
		.parse::<usize>().expect("input-idx must be a positive integer");

	let secp = secp256k1::Secp256k1::new();
	let desc = miniscript::Descriptor::<DescriptorPublicKey>::from_str(desc).expect("Error parsing descriptor");
	let desc = desc.derived_descriptor(0, &secp).expect("Hardened derivation");
	if i >= psbt.inputs.len() {
		panic!("Psbt input index out of range")
	}

	let mut psbt_inp = &mut psbt.inputs[i];
	match desc {
		Descriptor::Bare(..) |
		Descriptor::Pkh(..) |
		Descriptor::Wpkh(..) => todo!(),
		Descriptor::Sh(ref sh) => {
			match sh.as_inner() {
				miniscript::descriptor::ShInner::Wsh(wsh) => {
					psbt_inp.witness_script = Some(wsh.inner_script());
					psbt_inp.redeem_script = Some(desc.unsigned_script_sig());
				},
				miniscript::descriptor::ShInner::Wpkh(_wpkh) => {},
				miniscript::descriptor::ShInner::SortedMulti(svm) => {
					psbt_inp.redeem_script = Some(svm.encode());
				},
				miniscript::descriptor::ShInner::Ms(ms) => {
					psbt_inp.redeem_script = Some(ms.encode());
				},
			}
		},
		Descriptor::Wsh(ref wsh) => {
			psbt_inp.witness_script = Some(wsh.inner_script());
		},
		Descriptor::Tr(ref tr) => {
			psbt_inp.tap_internal_key = Some(tr.internal_key().to_x_only_pubkey());
			let spend_info = tr.spend_info();
			psbt_inp.tap_merkle_root = spend_info.merkle_root();
			for (_depth, ms ) in tr.iter_scripts() {
				let ver_script = (ms.encode(), LeafVersion::TapScript);
				let ctrl_block = spend_info.control_block(&ver_script)
					.expect("Unexpected Error while computing control block");
				psbt_inp.tap_scripts.insert(ctrl_block, ver_script);
			}
		},
	}
	let raw = serialize(&psbt);
	if let Some(path) = matches.value_of("output") {
		let mut file = File::create(&path).expect("failed to open output file");
		file.write_all(&raw).expect("error writing output file");
	} else if matches.is_present("raw-stdout") {
		::std::io::stdout().write_all(&raw).unwrap();
	} else {
		match source {
			PsbtSource::Hex => println!("{}", hex::encode(&raw)),
			PsbtSource::Base64 => println!("{}", base64::encode(&raw)),
			PsbtSource::File => {
				let path = matches.value_of("psbt").unwrap();
				let mut file = File::create(&path).expect("failed to PSBT file for writing");
				file.write_all(&raw).expect("error writing PSBT file");
			}
		}
	}
}

// Get the scriptpubkey/amount for the psbt input
fn get_spk_amt(psbt: &psbt::PartiallySignedTransaction, index: usize) -> (&bitcoin::Script, u64) {
	let script_pubkey;
	let amt;
	let inp = &psbt.inputs[index];
	if let Some(ref witness_utxo) = inp.witness_utxo {
		script_pubkey = &witness_utxo.script_pubkey;
		amt = witness_utxo.value;
	} else if let Some(ref non_witness_utxo) = inp.non_witness_utxo {
		let vout = psbt.unsigned_tx.input[index].previous_output.vout;
		script_pubkey = &non_witness_utxo.output[vout as usize].script_pubkey;
		amt = non_witness_utxo.output[vout as usize].value;
	} else {
		panic!("Psbt missing both witness and non-witness utxo")
	}
	(script_pubkey, amt)
}

// Get the spending utxo for this psbt input
// Should be rust-bitcoin method
fn get_utxo(psbt: &psbt::PartiallySignedTransaction, index: usize) -> &bitcoin::TxOut {
    let inp = &psbt.inputs[index];
    let utxo = if let Some(ref witness_utxo) = inp.witness_utxo {
        &witness_utxo
    } else if let Some(ref non_witness_utxo) = inp.non_witness_utxo {
        let vout = psbt.unsigned_tx.input[index].previous_output.vout;
        &non_witness_utxo.output[vout as usize]
    } else {
		panic!("Missing psbt utxo")
    };
    utxo
}

/// Get the Prevouts for the psbt
/// Should be updated to rust-bitcoin
fn prevouts<'a>(psbt: &'a psbt::PartiallySignedTransaction) -> Vec<bitcoin::TxOut> {
    let mut utxos = vec![];
    for i in 0..psbt.inputs.len() {
        let utxo_ref = get_utxo(psbt, i);
        utxos.push(utxo_ref.clone()); // RC fix would allow references here instead of clone
    }
	utxos
}


fn exec_rawsign<'a>(matches: &clap::ArgMatches<'a>) {
	let (raw, source) = file_or_raw(&matches.value_of("psbt").unwrap());
	let mut psbt: psbt::PartiallySignedTransaction = deserialize(&raw).expect("invalid PSBT format");

	let priv_key = matches.value_of("priv-key").expect("no key provided");
	let i = matches.value_of("input-idx").expect("Input index not provided")
		.parse::<usize>().expect("input-idx must be a positive integer");
	let compressed = matches.value_of("compressed").unwrap()
		.parse::<bool>().expect("Compressed must be boolean");

	if i >= psbt.inputs.len() {
		panic!("Psbt input index out of range")
	}
	let (spk, amt) = get_spk_amt(&psbt, i);
	// let redeem_script = psbt.inputs[i].redeem_script.as_ref().map(|x|
	// 	bitcoin::blockdata::script::Builder::new()
	// 	.push_slice(x.as_bytes())
	// 	.into_script());
	// let witness_script = psbt.inputs[i].witness_script.as_ref()
	// 	.map(|x| vec![x.clone().into_bytes()]);
	// let witness = bitcoin::Witness::from_vec(witness_script.unwrap_or(Vec::new()));
	// let script_sig = redeem_script.unwrap_or(bitcoin::Script::new());

	// Call with age and height 0.
	// TODO: Create a method to rust-bitcoin psbt that outputs sighash
	// Workaround using miniscript interpreter
	let mut cache = bitcoin::util::sighash::SigHashCache::new(&psbt.unsigned_tx);
	let sk = if let Ok(privkey) = PrivateKey::from_str(&priv_key) {
		privkey.inner
	} else if let Ok(sk) = secp256k1::SecretKey::from_str(&priv_key) {
		sk
	} else {
		panic!("invalid WIF/hex private key: {}", priv_key);
	};
	let secp = secp256k1::Secp256k1::new();
	let utxos = prevouts(&psbt);
    let utxos = &bitcoin::util::sighash::Prevouts::All(&utxos);
	if psbt.inputs[i].redeem_script.is_some() || psbt.inputs[i].witness_script.is_some() {
		let ecdsa_hash_ty = psbt.inputs[i].ecdsa_hash_ty().unwrap();
		let msg = if psbt.inputs[i].witness_script.is_some() {
			cache.segwit_signature_hash(i, spk, amt, ecdsa_hash_ty)
				.unwrap()
		} else {
			cache.legacy_signature_hash(i, spk, ecdsa_hash_ty.as_u32())
				.unwrap()
		};
		let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk);
		let pk = bitcoin::PublicKey {
			compressed: compressed,
			inner: pk,
		};
		let msg = secp256k1::Message::from_slice(msg.as_ref()).unwrap();
		let secp_sig = secp.sign_ecdsa(&msg, &sk);
		let btc_sig = bitcoin::EcdsaSig {
			sig: secp_sig,
			hash_ty: bitcoin::EcdsaSigHashType::All,
		};
		// mutate the psbt
		psbt.inputs[i].partial_sigs.insert(pk, btc_sig);
	} else if psbt.inputs[i].tap_internal_key.is_some() || !psbt.inputs[i].tap_scripts.is_empty() {
		let schnorr_sighash_ty = psbt.inputs[i].schnorr_hash_ty().unwrap();
		let keypair = secp256k1::KeyPair::from_secret_key(&secp, sk);
		let entropy: [u8; 32] = rand::random();
		let pk = XOnlyPublicKey::from_keypair(&keypair);
		let is_key_spend = Some(pk) == psbt.inputs[i].tap_internal_key;
		if is_key_spend {
			let msg = cache.taproot_key_spend_signature_hash(i, &utxos, schnorr_sighash_ty).expect("SigHash Calculation error");
			let msg = secp256k1::Message::from_slice(&msg).expect("32 byte");
			let tweaked_keypair = keypair.tap_tweak(&secp, psbt.inputs[i].tap_merkle_root);
			let schnorr_sig = secp.sign_schnorr_with_aux_rand(&msg, &tweaked_keypair.into_inner(), &entropy);
			let btc_sig = bitcoin::SchnorrSig {
				sig: schnorr_sig,
				hash_ty: bitcoin::SchnorrSigHashType::Default,
			};
			psbt.inputs[i].tap_key_sig = Some(btc_sig);
		} else {}
		for (_ctrl_blk, (script, _ver)) in  psbt.inputs[i].tap_scripts.iter() {
			let ms = Miniscript::<XOnlyPublicKey, Tap>::parse_insane(script).expect("Not a taproot miniscript");
			if let Some(xpk) = ms.iter_pk().find(|x| pk == *x) {
				let leaf_hash = TapLeafHash::from_script(script, LeafVersion::TapScript);
				let msg = cache.taproot_script_spend_signature_hash (i, &utxos, leaf_hash, schnorr_sighash_ty)
					.unwrap();
				let msg = secp256k1::Message::from_slice(&msg).expect("32 byte");
				let schnorr_sig = secp.sign_schnorr_with_aux_rand(&msg, &keypair, &entropy);
				let btc_sig = bitcoin::SchnorrSig {
					sig: schnorr_sig,
					hash_ty: bitcoin::SchnorrSigHashType::Default,
				};
				psbt.inputs[i].tap_script_sigs.insert((xpk, leaf_hash), btc_sig);
				break;
			} else {
				continue;
			}
		}
	} else {
		panic!("Unknown sighash method")
	}
	let raw = serialize(&psbt);
	if let Some(path) = matches.value_of("output") {
		let mut file = File::create(&path).expect("failed to open output file");
		file.write_all(&raw).expect("error writing output file");
	} else if matches.is_present("raw-stdout") {
		::std::io::stdout().write_all(&raw).unwrap();
	} else {
		match source {
			PsbtSource::Hex => println!("{}", hex::encode(&raw)),
			PsbtSource::Base64 => println!("{}", base64::encode(&raw)),
			PsbtSource::File => {
				let path = matches.value_of("psbt").unwrap();
				let mut file = File::create(&path).expect("failed to PSBT file for writing");
				file.write_all(&raw).expect("error writing PSBT file");
			}
		}
	}
}