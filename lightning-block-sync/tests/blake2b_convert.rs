// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Version 2 (BLAKE2b) headers survive the trip through JSON.
//!
//! A verbose `getblockheader` result is the only place a `Header` is built
//! from named fields rather than from its serialization, so it is the one
//! place a v2 header can quietly lose the fields that decide its hash. These
//! tests pin that conversion against data neither of them invented: Bitcoin
//! Knots' own header vectors, and a capture from a running Knots regtest node
//! across the activation height.

#![cfg(all(feature = "blake2b", feature = "rpc-client"))]

use bitcoin::consensus::encode;
use bitcoin::hashes::Hash;
use bitcoin::hex::DisplayHex;
use lightning_block_sync::http::JsonResponse;
use lightning_block_sync::poll::Validate;
use lightning_block_sync::BlockHeaderData;

use std::convert::TryInto;

/// Any 32-byte value; `chainwork` is not what these tests are about.
const SOME_CHAINWORK: &str = "0000000000000000000000000000000000000000000000000000000000000123";

fn header_from(json: serde_json::Value) -> BlockHeaderData {
	TryInto::<BlockHeaderData>::try_into(JsonResponse(json)).expect("header should convert")
}

/// Knots' own header vectors, reshaped into what its RPC would return for the
/// same header.
///
/// The vectors carry non-zero `extranonce`, `xor_key` and `mm_rhs`, which a
/// regtest chain does not, so this is what proves the byte order. It also
/// covers all four ASIC profiles and a header that uses the time offset.
#[test]
fn knots_vectors_survive_the_json_round_trip() {
	let data: serde_json::Value =
		serde_json::from_str(include_str!("data/block_header_v2.json")).unwrap();
	let vectors = data["headers"].as_array().unwrap();
	assert_eq!(vectors.len(), 5, "all the vectors, or the file changed under us");

	let mut profiles_seen = [false; 4];

	for vector in vectors {
		let name = vector["name"].as_str().unwrap();
		let f = &vector["fields"];
		let bits = u32::try_from(f["nBits"].as_u64().unwrap()).unwrap();

		// Exactly the field set blockheaderToJSON emits for a v2 header.
		let rpc = serde_json::json!({
			"chainwork": SOME_CHAINWORK,
			"height": f["m_height"],
			"version": f["nVersion"],
			"previousblockhash": f["hashPrevBlock"],
			"merkleroot": f["hashMerkleRoot"],
			"time": f["nTime"],
			"bits": bits.to_be_bytes().as_hex().to_string(),
			"nonce": f["nNonce"],
			"headerv": 2,
			"nonce2": f["m_nonce2"],
			"nonce3": f["m_nonce3"],
			"extranonce": f["m_extranonce"],
			"flags": f["m_flags"],
			"time_offset": f["m_time_offset"],
			"txcount": f["m_txcount"],
			"xor_key": f["m_xor_key"],
			"xor_key_mask_clear_bits": f["m_xor_key_mask_clear_bits"],
			"mm_rhs": f["m_mm_rhs"],
		});

		let header = header_from(rpc).header;
		let v2 = header.v2.as_ref().unwrap_or_else(|| panic!("{name}: v2 payload dropped"));

		let profile = usize::from(v2.asic_profile());
		profiles_seen[profile] = true;

		// The header Knots serialized, rebuilt from named fields alone.
		assert_eq!(
			encode::serialize(&header).as_hex().to_string(),
			vector["serialized"].as_str().unwrap(),
			"{name}: serialization differs",
		);
		assert_eq!(
			header.block_hash().to_string(),
			vector["block_hash"].as_str().unwrap(),
			"{name}: proof-of-work hash differs",
		);
	}

	assert_eq!(profiles_seen, [true; 4], "every ASIC profile should be covered");
}

/// A real chain, captured either side of the activation height.
#[test]
fn a_knots_chain_converts_across_activation() {
	let data: serde_json::Value =
		serde_json::from_str(include_str!("data/regtest_activation.json")).unwrap();
	let captures = data["headers"].as_array().unwrap();

	let mut previous: Option<(u64, bitcoin::BlockHash)> = None;

	for capture in captures {
		let json = capture["json"].clone();
		let height = json["height"].as_u64().unwrap();
		let reported_hash = json["hash"].as_str().unwrap().to_owned();
		let headerv = json["headerv"].as_u64().unwrap();

		let data = header_from(json);
		let header = data.header;

		assert_eq!(u64::from(data.height), height);

		match headerv {
			1 => assert!(header.v2.is_none(), "height {height} is a v1 header"),
			2 => assert!(header.v2.is_some(), "height {height} is a v2 header"),
			_ => unreachable!(),
		}

		// The whole point: the header we rebuilt is the header the node has.
		assert_eq!(
			encode::serialize(&header).as_hex().to_string(),
			capture["serialized"].as_str().unwrap(),
			"height {height}: serialization differs",
		);
		assert_eq!(
			header.block_hash().to_string(),
			reported_hash,
			"height {height}: hash differs from the one the RPC reported",
		);

		// And it chains — including the v2 block onto its v1 parent.
		if let Some((parent_height, parent_hash)) = previous {
			assert_eq!(parent_height + 1, height, "captures should be consecutive");
			assert_eq!(
				header.prev_blockhash, parent_hash,
				"height {height} should link to height {parent_height}",
			);
		}
		previous = Some((height, header.block_hash()));
	}

	assert_eq!(previous.map(|(h, _)| h), Some(21), "should have walked to height 21");
}

/// Bitcoin Core has no `headerv`, and Knots reports 1 before the fork. Both
/// must read as a v1 header rather than as an error or an empty v2 payload.
#[test]
fn a_node_without_v2_headers_is_unaffected() {
	let base = serde_json::json!({
		"chainwork": SOME_CHAINWORK,
		"height": 19,
		"version": 536870912,
		"previousblockhash": "254ca202d505d7d97cc0a98fbce7043748eb30caacb555468d268fbf336ca224",
		"merkleroot": "223de7cee6ac70d7e0009d97cec27aa0188895aca21c08ce114d2bc7f2a851eb",
		"time": 1788088853u64,
		"bits": "207fffff",
		"nonce": 1,
	});

	// A pre-fork node: no "headerv" at all.
	let core = header_from(base.clone()).header;
	assert!(core.v2.is_none());
	assert_eq!(encode::serialize(&core).len(), 80);

	// Knots below the activation height.
	let mut knots_v1 = base.clone();
	knots_v1["headerv"] = serde_json::json!(1);
	assert_eq!(header_from(knots_v1).header, core);

	// A format we do not know is an error, not a guess.
	let mut future = base;
	future["headerv"] = serde_json::json!(3);
	assert!(TryInto::<BlockHeaderData>::try_into(JsonResponse(future)).is_err());
}

/// A v2 header missing one of its fields must fail, not silently hash wrong.
#[test]
fn an_incomplete_v2_header_is_rejected() {
	let data: serde_json::Value =
		serde_json::from_str(include_str!("data/regtest_activation.json")).unwrap();
	let complete = data["headers"][1]["json"].clone();
	assert_eq!(complete["headerv"], 2);

	for field in
		["nonce2", "nonce3", "extranonce", "flags", "time_offset", "txcount", "xor_key",
		 "xor_key_mask_clear_bits", "mm_rhs"]
	{
		let mut missing = complete.clone();
		missing.as_object_mut().unwrap().remove(field);
		assert!(
			TryInto::<BlockHeaderData>::try_into(JsonResponse(missing)).is_err(),
			"a v2 header without \"{field}\" should be rejected",
		);
	}
}

/// Whole blocks come over as raw hex, not as named fields, so this exercises
/// the decoder rather than the conversion — but it is the other half of the
/// path LDK uses, and a 164-byte header inside a block is where a v1-only
/// decoder gives up.
#[test]
fn a_block_with_a_v2_header_deserialises() {
	let data: serde_json::Value =
		serde_json::from_str(include_str!("data/regtest_activation.json")).unwrap();

	let mut seen = 0;
	for capture in data["headers"].as_array().unwrap() {
		let Some(hex) = capture["block"].as_str() else { continue };
		let headerv = capture["json"]["headerv"].as_u64().unwrap();
		let height = capture["json"]["height"].as_u64().unwrap();

		let block: bitcoin::Block =
			TryInto::<bitcoin::Block>::try_into(JsonResponse(serde_json::json!(hex)))
				.unwrap_or_else(|e| panic!("height {height}: {e}"));

		assert_eq!(block.header.v2.is_some(), headerv == 2);
		assert_eq!(
			block.block_hash().to_string(),
			capture["json"]["hash"].as_str().unwrap(),
			"height {height}: block hash differs",
		);
		// The header inside the block is the header the RPC described.
		assert_eq!(
			encode::serialize(&block.header).as_hex().to_string(),
			capture["serialized"].as_str().unwrap(),
		);
		if headerv == 2 {
			assert_eq!(
				usize::from(block.header.v2.as_ref().unwrap().txcount),
				block.txdata.len(),
				"height {height}: the header\'s txcount should match the block",
			);
		}
		seen += 1;
	}
	assert_eq!(seen, 2, "should have covered a v1 and a v2 block");
}

/// What the poller does with a header once it has one.
///
/// `Validate` re-derives the proof-of-work hash and refuses the header unless
/// it matches the one the source reported, so it is the check that would catch
/// a v2 header hashed as if it were v1 — and the check that a v1-only client
/// silently fails. Nothing about it needed changing for v2: the target comes
/// from the header's own nBits, and `validate_pow` goes through
/// `block_hash()`, which knows the difference.
#[test]
fn a_v2_header_passes_proof_of_work_validation() {
	let data: serde_json::Value =
		serde_json::from_str(include_str!("data/regtest_activation.json")).unwrap();

	for capture in data["headers"].as_array().unwrap() {
		let json = capture["json"].clone();
		let height = json["height"].as_u64().unwrap();
		let hash: bitcoin::BlockHash = json["hash"].as_str().unwrap().parse().unwrap();

		let validated = header_from(json)
			.validate(hash)
			.unwrap_or_else(|e| panic!("height {height}: {e:?}"));
		assert_eq!(validated.header.block_hash(), hash);

		// And it is refused for a hash that is not its own.
		let wrong = bitcoin::BlockHash::from_byte_array([7u8; 32]);
		assert!(header_from(capture["json"].clone()).validate(wrong).is_err());
	}
}
