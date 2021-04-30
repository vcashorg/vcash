// Copyright 2019 The Grin Developers
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! core consensus.rs tests (separated to de-clutter consensus.rs)
use grin_core as core;

use self::core::consensus::*;
//use self::core::core::block::HeaderVersion;
use self::core::global;
use self::core::pow::compact_to_diff;
use self::core::pow::Difficulty;
use chrono::prelude::{TimeZone, Utc};
use std::fmt::{self, Display};

/// Last n blocks for difficulty calculation purposes
/// (copied from stats in server crate)
#[derive(Clone, Debug)]
pub struct DiffBlock {
	/// Block number (can be negative for a new chain)
	pub block_number: i64,
	/// Block network difficulty
	pub difficulty: u64,
	/// Time block was found (epoch seconds)
	pub time: u64,
	/// Duration since previous block (epoch seconds)
	pub duration: u64,
}

/// Stats on the last WINDOW blocks and the difficulty calculation
/// (Copied from stats in server crate)
#[derive(Clone)]
pub struct DiffStats {
	/// latest height
	pub height: u64,
	/// Last WINDOW block data
	pub last_blocks: Vec<DiffBlock>,
	/// Average block time for last WINDOW blocks
	pub average_block_time: u64,
	/// Average WINDOW difficulty
	pub average_difficulty: u64,
	/// WINDOW size
	pub window_size: u64,
	/// Block time sum
	pub block_time_sum: u64,
	/// Block diff sum
	pub block_diff_sum: u64,
	/// latest ts
	pub latest_ts: u64,
	/// earliest ts
	pub earliest_ts: u64,
	/// ts delta
	pub ts_delta: u64,
}

impl Display for DiffBlock {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let output = format!(
			"Block Number: {} Difficulty: {}, Time: {}, Duration: {}",
			self.block_number, self.difficulty, self.time, self.duration
		);
		Display::fmt(&output, f)
	}
}

// Builds an iterator for next difficulty calculation with the provided
// constant time interval, difficulty and total length.
fn repeat(interval: u64, diff: HeaderInfo, len: u64, cur_time: Option<u64>) -> Vec<HeaderInfo> {
	let cur_time = match cur_time {
		Some(t) => t,
		None => Utc::now().timestamp() as u64,
	};
	// watch overflow here, length shouldn't be ridiculous anyhow
	assert!(len < std::usize::MAX as u64);
	let diffs = vec![diff.difficulty.clone(); len as usize];
	let times = (0..(len as usize)).map(|n| n * interval as usize).rev();
	let pairs = times.zip(diffs.iter());
	pairs
		.map(|(t, d)| {
			HeaderInfo::new(
				diff.block_hash,
				cur_time + t as u64,
				d.clone(),
				diff.secondary_scaling,
				diff.is_secondary,
			)
		})
		.collect::<Vec<_>>()
}

// Creates a new chain with a genesis at a simulated difficulty
fn create_chain_sim(diff: u64) -> Vec<(HeaderInfo, DiffStats)> {
	println!(
		"adding create: {}, {}",
		Utc::now().timestamp(),
		Difficulty::from_num(diff)
	);
	let return_vec = vec![HeaderInfo::from_ts_diff(
		Utc::now().timestamp() as u64,
		Difficulty::from_num(diff),
	)];
	let diff_stats = get_diff_stats(&return_vec);
	vec![(
		HeaderInfo::from_ts_diff(Utc::now().timestamp() as u64, Difficulty::from_num(diff)),
		diff_stats,
	)]
}

fn get_diff_stats(chain_sim: &Vec<HeaderInfo>) -> DiffStats {
	// Fill out some difficulty stats for convenience
	let diff_iter = chain_sim.clone();
	let last_blocks: Vec<HeaderInfo> = global::difficulty_data_to_vector(diff_iter.iter().cloned());

	let mut last_time = last_blocks[0].timestamp;
	let tip_height = chain_sim.len();
	let earliest_block_height = tip_height as i64 - last_blocks.len() as i64;

	let earliest_ts = last_blocks[0].timestamp;
	let latest_ts = last_blocks[last_blocks.len() - 1].timestamp;

	let mut i = 1;

	let sum_blocks: Vec<HeaderInfo> = global::difficulty_data_to_vector(diff_iter.iter().cloned())
		.into_iter()
		.take(DIFFICULTY_ADJUST_WINDOW_ORIGIN as usize)
		.collect();

	let sum_entries: Vec<DiffBlock> = sum_blocks
		.iter()
		//.skip(1)
		.map(|n| {
			let dur = n.timestamp - last_time;
			let height = earliest_block_height + i + 1;
			i += 1;
			last_time = n.timestamp;
			DiffBlock {
				block_number: height,
				difficulty: n.difficulty.to_num(),
				time: n.timestamp,
				duration: dur,
			}
		})
		.collect();

	let block_time_sum = sum_entries.iter().fold(0, |sum, t| sum + t.duration);
	let block_diff_sum = sum_entries.iter().fold(0, |sum, d| sum + d.difficulty);

	i = 1;
	last_time = last_blocks[0].clone().timestamp;

	let diff_entries: Vec<DiffBlock> = last_blocks
		.iter()
		.skip(1)
		.map(|n| {
			let dur = n.timestamp - last_time;
			let height = earliest_block_height + i;
			i += 1;
			last_time = n.timestamp;
			DiffBlock {
				block_number: height,
				difficulty: n.difficulty.to_num(),
				time: n.timestamp,
				duration: dur,
			}
		})
		.collect();

	DiffStats {
		height: tip_height as u64,
		last_blocks: diff_entries,
		average_block_time: block_time_sum / (DIFFICULTY_ADJUST_WINDOW_ORIGIN),
		average_difficulty: block_diff_sum / (DIFFICULTY_ADJUST_WINDOW_ORIGIN),
		window_size: DIFFICULTY_ADJUST_WINDOW_ORIGIN,
		block_time_sum: block_time_sum,
		block_diff_sum: block_diff_sum,
		latest_ts: latest_ts,
		earliest_ts: earliest_ts,
		ts_delta: latest_ts - earliest_ts,
	}
}

// Adds another 'block' to the iterator, so to speak, with difficulty calculated
// from the difficulty adjustment at interval seconds from the previous block
fn add_block(
	interval: u64,
	chain_sim: Vec<(HeaderInfo, DiffStats)>,
) -> Vec<(HeaderInfo, DiffStats)> {
	let mut ret_chain_sim = chain_sim.clone();
	let mut return_chain: Vec<HeaderInfo> = chain_sim.clone().iter().map(|e| e.0.clone()).collect();
	// get last interval
	let diff = next_difficulty(1, return_chain.clone());
	let last_elem = chain_sim.first().unwrap().clone().0;
	let time = last_elem.timestamp + interval;
	return_chain.insert(0, HeaderInfo::from_ts_diff(time, diff.difficulty));
	let diff_stats = get_diff_stats(&return_chain);
	ret_chain_sim.insert(
		0,
		(HeaderInfo::from_ts_diff(time, diff.difficulty), diff_stats),
	);
	ret_chain_sim
}

// Adds another n 'blocks' to the iterator, with difficulty calculated
fn add_block_repeated(
	interval: u64,
	chain_sim: Vec<(HeaderInfo, DiffStats)>,
	iterations: usize,
) -> Vec<(HeaderInfo, DiffStats)> {
	let mut return_chain = chain_sim.clone();
	for _ in 0..iterations {
		return_chain = add_block(interval, return_chain.clone());
	}
	return_chain
}

// Prints the contents of the iterator and its difficulties.. useful for
// tweaking
fn print_chain_sim(chain_sim: Vec<(HeaderInfo, DiffStats)>) {
	let mut chain_sim = chain_sim.clone();
	chain_sim.reverse();
	let mut last_time = 0;
	let mut first = true;
	println!("Constants");
	println!(
		"DIFFICULTY_ADJUST_WINDOW: {}",
		DIFFICULTY_ADJUST_WINDOW_ORIGIN
	);
	println!("BLOCK_TIME_WINDOW: {}", BLOCK_TIME_WINDOW);
	println!("CLAMP_FACTOR: {}", CLAMP_FACTOR);
	println!("DAMP_FACTOR: {}", DIFFICULTY_DAMP_FACTOR);
	chain_sim.iter().enumerate().for_each(|(i, b)| {
		let block = b.0.clone();
		let stats = b.1.clone();
		if first {
			last_time = block.timestamp;
			first = false;
		}
		println!(
			"Height: {}, Time: {}, Interval: {}, Network difficulty:{}, Average Block Time: {}, Average Difficulty {}, Block Time Sum: {}, Block Diff Sum: {}, Latest Timestamp: {}, Earliest Timestamp: {}, Timestamp Delta: {}",
			i,
			block.timestamp,
			block.timestamp - last_time,
			block.difficulty,
			stats.average_block_time,
			stats.average_difficulty,
			stats.block_time_sum,
			stats.block_diff_sum,
			stats.latest_ts,
			stats.earliest_ts,
			stats.ts_delta,
		);
		let mut sb = stats.last_blocks.clone();
		sb.reverse();
		for i in sb {
			println!("   {}", i);
		}
		last_time = block.timestamp;
	});
}

fn repeat_offs(from: u64, interval: u64, diff: u64, len: u64) -> Vec<HeaderInfo> {
	repeat(
		interval,
		HeaderInfo::from_ts_diff(1, Difficulty::from_num(diff)),
		len,
		Some(from),
	)
}

#[test]
fn test_halving_height() {
	global::set_local_chain_type(global::ChainTypes::Mainnet);
	assert_eq!(global::third_hard_fork_height(), 80640);
	//first halving
	assert_eq!(first_halving_height(), 727440);
	//second halving
	assert_eq!(first_halving_height() + global::halving_interval(), 1777440);
	//third halving
	assert_eq!(
		first_halving_height() + 2 * global::halving_interval(),
		2827440
	);
}

#[test]
fn test_reward() {
	global::set_local_chain_type(global::ChainTypes::Mainnet);

	//before third_hard_fork
	let before_third_hard_fork_height_reward = REWARD_ORIGIN;
	assert_eq!(
		reward(global::third_hard_fork_height() - 1, 0),
		before_third_hard_fork_height_reward
	);

	//third_hard_fork
	let third_hard_fork_height_reward = REWARD_ADJUSTED;
	assert_eq!(
		reward(global::third_hard_fork_height(), 0),
		third_hard_fork_height_reward
	);

	//before first halving
	let before_first_halving_height_reward = REWARD_ADJUSTED;
	assert_eq!(
		reward(first_halving_height() - 1, 0),
		before_first_halving_height_reward
	);

	//first halving
	let first_halving_height_reward = REWARD_ADJUSTED / 2;
	assert_eq!(
		reward(first_halving_height(), 0),
		first_halving_height_reward
	);

	//before second halving
	let before_second_halving_height_reward = REWARD_ADJUSTED / 2;
	assert_eq!(
		reward(first_halving_height() + global::halving_interval() - 1, 0),
		before_second_halving_height_reward
	);

	//second halving
	let second_halving_height_reward = REWARD_ADJUSTED / 4;
	assert_eq!(
		reward(first_halving_height() + global::halving_interval(), 0),
		second_halving_height_reward
	);
}

#[test]
fn test_total_reward() {
	global::set_local_chain_type(global::ChainTypes::Mainnet);
	let total = 21000000 as f64;
	assert_eq!(total_reward(0, true), 50 * GRIN_BASE as u64);
	let third_hard_fork = 4032000 as f64;
	let first_half = total * 0.5;
	let second_half = total * 0.75;
	let third_half = total * 0.875;

	//before third_hard_fork
	assert_eq!(
		total_reward(global::third_hard_fork_height() - 1, true),
		(third_hard_fork * GRIN_BASE as f64) as u64
	);

	//third_hard_fork
	assert_eq!(
		total_reward(global::third_hard_fork_height(), true),
		((third_hard_fork + 10 as f64) * GRIN_BASE as f64) as u64
	);

	//before first halving
	assert_eq!(
		total_reward(first_halving_height() - 1, true),
		(first_half * GRIN_BASE as f64) as u64
	);

	//first halving
	assert_eq!(
		total_reward(first_halving_height(), true),
		((first_half + 5 as f64) * GRIN_BASE as f64) as u64
	);

	//before second halving
	assert_eq!(
		total_reward(
			first_halving_height() + global::halving_interval() - 1,
			true
		),
		(second_half * GRIN_BASE as f64) as u64
	);

	//second halving
	assert_eq!(
		total_reward(first_halving_height() + global::halving_interval(), true),
		((second_half + 2.5) * GRIN_BASE as f64) as u64
	);

	//before third halving
	assert_eq!(
		total_reward(
			first_halving_height() + 2 * global::halving_interval() - 1,
			true
		),
		(third_half * GRIN_BASE as f64) as u64
	);

	//third halving
	assert_eq!(
		total_reward(
			first_halving_height() + 2 * global::halving_interval(),
			true
		),
		((third_half + 1.25) * GRIN_BASE as f64) as u64
	);
}

#[test]
fn test_next_bit_difficulty() {
	global::set_local_chain_type(global::ChainTypes::Mainnet);
	//before third_hard_fork: not on adjust window
	let compact0 = next_bit_difficulty(
		2016,
		0x180ffff0, // 2^36
		Utc.ymd(2019, 3, 1).and_hms(0, 0, 0).timestamp(),
		Utc.ymd(2019, 1, 1).and_hms(0, 0, 0).timestamp(),
	);
	assert_eq!(compact_to_diff(compact0), 68719476736_u64);

	//before third_hard_fork:mainnet min diff is 0x18120f14, as 60883825480,
	let compact0 = next_bit_difficulty(
		2016 * 2 - 1,
		0x180ffff0, // 2^36
		Utc.ymd(2019, 3, 1).and_hms(0, 0, 0).timestamp(),
		Utc.ymd(2019, 1, 1).and_hms(0, 0, 0).timestamp(),
	);
	assert_eq!(compact_to_diff(compact0), 60883825480_u64);

	//before third_hard_fork: diff * 2
	let compact1 = next_bit_difficulty(
		2016 * 3 - 1,
		0x1800ffff, // 2^40
		Utc.ymd(2019, 3, 8).and_hms(0, 0, 0).timestamp(),
		Utc.ymd(2019, 3, 1).and_hms(0, 0, 0).timestamp(),
	);
	assert_eq!(compact_to_diff(compact1), 2199023255552_u64); //2199023255552_u64 is 2^41

	//before third_hard_fork: diff * 4
	let compact1 = next_bit_difficulty(
		2016 * 4 - 1,
		0x1800ffff, // 2^40
		Utc.ymd(2019, 3, 2).and_hms(0, 0, 0).timestamp(),
		Utc.ymd(2019, 3, 1).and_hms(0, 0, 0).timestamp(),
	);
	assert_eq!(compact_to_diff(compact1), 4398046511104_u64); //4398046511104_u64 is 2^42

	//before third_hard_fork:diff / 4
	let compact2 = next_bit_difficulty(
		2016 * 5 - 1,
		0x1800ffff, // 2^40
		Utc.ymd(2019, 3, 1).and_hms(0, 0, 0).timestamp(),
		Utc.ymd(2018, 3, 1).and_hms(0, 0, 0).timestamp(),
	);
	assert_eq!(compact_to_diff(compact2), 274877906944_u64); //274877906944_u64 is 2^38

	//at third_hard_fork  diff / 5
	let compact3 = next_bit_difficulty(
		global::third_hard_fork_height() - 1,
		0x1800ffff, // 2^40
		Utc.ymd(2019, 3, 15).and_hms(0, 0, 0).timestamp(),
		Utc.ymd(2019, 3, 1).and_hms(0, 0, 0).timestamp(),
	);
	assert_eq!(compact_to_diff(compact3), 219902325555_u64);

	//at third_hard_fork  diff / 10
	let compact3 = next_bit_difficulty(
		global::third_hard_fork_height() - 1,
		0x1800ffff, // 2^40
		Utc.ymd(2019, 3, 29).and_hms(0, 0, 0).timestamp(),
		Utc.ymd(2019, 3, 1).and_hms(0, 0, 0).timestamp(),
	);
	assert_eq!(compact_to_diff(compact3), 109951162777_u64);

	//after third_hard_fork: not on adjust window
	let compact0 = next_bit_difficulty(
		global::third_hard_fork_height() + 10080,
		0x180ffff0, // 2^36
		Utc.ymd(2019, 3, 1).and_hms(0, 0, 0).timestamp(),
		Utc.ymd(2019, 1, 1).and_hms(0, 0, 0).timestamp(),
	);
	assert_eq!(compact_to_diff(compact0), 68719476736_u64);

	//after third_hard_fork:mainnet min diff is 0x18120f14, as 60883825480,
	let compact0 = next_bit_difficulty(
		global::third_hard_fork_height() + 10080 - 1,
		0x180ffff0, // 2^36
		Utc.ymd(2019, 3, 1).and_hms(0, 0, 0).timestamp(),
		Utc.ymd(2019, 1, 1).and_hms(0, 0, 0).timestamp(),
	);
	assert_eq!(compact_to_diff(compact0), 60883825480_u64);

	//after third_hard_fork: diff * 2
	let compact1 = next_bit_difficulty(
		global::third_hard_fork_height() + 10080 * 2 - 1,
		0x1800ffff, // 2^40
		Utc.ymd(2019, 3, 8).and_hms(0, 0, 0).timestamp(),
		Utc.ymd(2019, 3, 1).and_hms(0, 0, 0).timestamp(),
	);
	assert_eq!(compact_to_diff(compact1), 2199023255552_u64); //2199023255552_u64 is 2^41

	//after third_hard_fork: diff * 4
	let compact1 = next_bit_difficulty(
		global::third_hard_fork_height() + 10080 * 3 - 1,
		0x1800ffff, // 2^40
		Utc.ymd(2019, 3, 2).and_hms(0, 0, 0).timestamp(),
		Utc.ymd(2019, 3, 1).and_hms(0, 0, 0).timestamp(),
	);
	assert_eq!(compact_to_diff(compact1), 4398046511104_u64); //4398046511104_u64 is 2^42

	//after third_hard_fork:diff / 4
	let compact2 = next_bit_difficulty(
		global::third_hard_fork_height() + 10080 * 4 - 1,
		0x1800ffff, // 2^40
		Utc.ymd(2019, 3, 1).and_hms(0, 0, 0).timestamp(),
		Utc.ymd(2018, 3, 1).and_hms(0, 0, 0).timestamp(),
	);
	assert_eq!(compact_to_diff(compact2), 274877906944_u64); //274877906944_u64 is 2^38
}

/// Checks different next_target adjustments and difficulty boundaries
#[test]
fn adjustment_scenarios() {
	// Use production parameters for genesis diff
	global::set_local_chain_type(global::ChainTypes::Mainnet);

	// Genesis block with initial diff
	let chain_sim = create_chain_sim(global::initial_block_difficulty());
	// Scenario 1) Hash power is massively over estimated, first block takes an hour
	let chain_sim = add_block_repeated(3600, chain_sim, 2);
	let chain_sim = add_block_repeated(1800, chain_sim, 2);
	let chain_sim = add_block_repeated(900, chain_sim, 10);
	let chain_sim = add_block_repeated(450, chain_sim, 30);
	let chain_sim = add_block_repeated(400, chain_sim, 30);
	let chain_sim = add_block_repeated(300, chain_sim, 30);

	println!("*********************************************************");
	println!("Scenario 1) Grossly over-estimated genesis difficulty ");
	println!("*********************************************************");
	print_chain_sim(chain_sim);
	println!("*********************************************************");

	// Under-estimated difficulty
	let chain_sim = create_chain_sim(global::initial_block_difficulty());
	let chain_sim = add_block_repeated(1, chain_sim, 5);
	let chain_sim = add_block_repeated(20, chain_sim, 5);
	let chain_sim = add_block_repeated(30, chain_sim, 20);

	println!("*********************************************************");
	println!("Scenario 2) Grossly under-estimated genesis difficulty ");
	println!("*********************************************************");
	print_chain_sim(chain_sim);
	println!("*********************************************************");
	let just_enough = 60 as usize; //DIFFICULTY_ADJUST_WINDOW is too big

	// Steady difficulty for a good while, then a sudden drop
	let chain_sim = create_chain_sim(global::initial_block_difficulty());
	let chain_sim = add_block_repeated(60, chain_sim, just_enough as usize);
	let chain_sim = add_block_repeated(600, chain_sim, 60);

	println!("");
	println!("*********************************************************");
	println!("Scenario 3) Sudden drop in hashpower");
	println!("*********************************************************");
	print_chain_sim(chain_sim);
	println!("*********************************************************");

	// Sudden increase
	let chain_sim = create_chain_sim(global::initial_block_difficulty());
	let chain_sim = add_block_repeated(60, chain_sim, just_enough as usize);
	let chain_sim = add_block_repeated(10, chain_sim, 10);

	println!("");
	println!("*********************************************************");
	println!("Scenario 4) Sudden increase in hashpower");
	println!("*********************************************************");
	print_chain_sim(chain_sim);
	println!("*********************************************************");

	// Oscillations
	let chain_sim = create_chain_sim(global::initial_block_difficulty());
	let chain_sim = add_block_repeated(60, chain_sim, just_enough as usize);
	let chain_sim = add_block_repeated(10, chain_sim, 10);
	let chain_sim = add_block_repeated(60, chain_sim, 20);
	let chain_sim = add_block_repeated(10, chain_sim, 10);

	println!("");
	println!("*********************************************************");
	println!("Scenario 5) Oscillations in hashpower");
	println!("*********************************************************");
	print_chain_sim(chain_sim);
	println!("*********************************************************");
}

/// Checks different next_target adjustments and difficulty boundaries
#[test]
#[ignore]
fn next_target_adjustment() {
	global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
	let cur_time = Utc::now().timestamp() as u64;
	let diff_min = Difficulty::min();

	// Check we don't get stuck on difficulty <= MIN_DIFFICULTY (at 4x faster blocks at least)
	let mut hi = HeaderInfo::from_diff_scaling(diff_min, AR_SCALE_DAMP_FACTOR as u32);
	hi.is_secondary = false;
	let hinext = next_difficulty(
		1,
		repeat(
			BLOCK_TIME_SEC_ORIGIN / 4,
			hi.clone(),
			BLOCK_TIME_SEC_ORIGIN,
			None,
		),
	);

	assert_ne!(hinext.difficulty, diff_min);

	// Check we don't get stuck on scale MIN_DIFFICULTY, when primary frequency is too high
	assert_ne!(hinext.secondary_scaling, MIN_DIFFICULTY as u32);

	// just enough data, right interval, should stay constant
	let just_enough = DIFFICULTY_ADJUST_WINDOW_ORIGIN + 1;
	hi.difficulty = Difficulty::from_num(10000);
	assert_eq!(
		next_difficulty(
			1,
			repeat(BLOCK_TIME_SEC_ORIGIN, hi.clone(), just_enough, None)
		)
		.difficulty,
		Difficulty::from_num(10000)
	);

	// check pre difficulty_data_to_vector effect on retargetting
	assert_eq!(
		next_difficulty(1, vec![HeaderInfo::from_ts_diff(42, hi.difficulty)]).difficulty,
		Difficulty::from_num(14913)
	);

	// checking averaging works
	hi.difficulty = Difficulty::from_num(500);
	let sec = DIFFICULTY_ADJUST_WINDOW_ORIGIN / 2;
	let mut s1 = repeat(BLOCK_TIME_SEC_ORIGIN, hi.clone(), sec, Some(cur_time));
	let mut s2 = repeat_offs(
		cur_time + (sec * BLOCK_TIME_SEC_ORIGIN) as u64,
		BLOCK_TIME_SEC_ORIGIN,
		1500,
		DIFFICULTY_ADJUST_WINDOW_ORIGIN / 2,
	);
	s2.append(&mut s1);
	assert_eq!(
		next_difficulty(1, s2).difficulty,
		Difficulty::from_num(1000)
	);

	// too slow, diff goes down
	hi.difficulty = Difficulty::from_num(1000);
	assert_eq!(
		next_difficulty(1, repeat(90, hi.clone(), just_enough, None)).difficulty,
		Difficulty::from_num(857)
	);
	assert_eq!(
		next_difficulty(1, repeat(120, hi.clone(), just_enough, None)).difficulty,
		Difficulty::from_num(750)
	);

	// too fast, diff goes up
	assert_eq!(
		next_difficulty(1, repeat(55, hi.clone(), just_enough, None)).difficulty,
		Difficulty::from_num(1028)
	);
	assert_eq!(
		next_difficulty(1, repeat(45, hi.clone(), just_enough, None)).difficulty,
		Difficulty::from_num(1090)
	);
	assert_eq!(
		next_difficulty(1, repeat(30, hi.clone(), just_enough, None)).difficulty,
		Difficulty::from_num(1200)
	);

	// hitting lower time bound, should always get the same result below
	assert_eq!(
		next_difficulty(1, repeat(0, hi.clone(), just_enough, None)).difficulty,
		Difficulty::from_num(1500)
	);

	// hitting higher time bound, should always get the same result above
	assert_eq!(
		next_difficulty(1, repeat(300, hi.clone(), just_enough, None)).difficulty,
		Difficulty::from_num(500)
	);
	assert_eq!(
		next_difficulty(1, repeat(400, hi.clone(), just_enough, None)).difficulty,
		Difficulty::from_num(500)
	);

	// We should never drop below minimum
	hi.difficulty = Difficulty::zero();
	assert_eq!(
		next_difficulty(1, repeat(90, hi.clone(), just_enough, None)).difficulty,
		Difficulty::min()
	);
}

#[test]
#[ignore]
fn test_secondary_pow_ratio() {
	// Tests for mainnet chain type.
	{
		global::set_local_chain_type(global::ChainTypes::Mainnet);
		assert_eq!(global::is_testnet(), false);

		assert_eq!(secondary_pow_ratio(1), 90);
		assert_eq!(secondary_pow_ratio(89), 90);
		assert_eq!(secondary_pow_ratio(90), 90);
		assert_eq!(secondary_pow_ratio(91), 90);
		assert_eq!(secondary_pow_ratio(179), 90);
		assert_eq!(secondary_pow_ratio(180), 90);
		assert_eq!(secondary_pow_ratio(181), 90);

		let one_week = 60 * 24 * 7;
		assert_eq!(secondary_pow_ratio(one_week - 1), 90);
		assert_eq!(secondary_pow_ratio(one_week), 90);
		assert_eq!(secondary_pow_ratio(one_week + 1), 90);

		let two_weeks = one_week * 2;
		assert_eq!(secondary_pow_ratio(two_weeks - 1), 89);
		assert_eq!(secondary_pow_ratio(two_weeks), 89);
		assert_eq!(secondary_pow_ratio(two_weeks + 1), 89);

		let t4_fork_height = 64_000;
		assert_eq!(secondary_pow_ratio(t4_fork_height - 1), 85);
		assert_eq!(secondary_pow_ratio(t4_fork_height), 85);
		assert_eq!(secondary_pow_ratio(t4_fork_height + 1), 85);

		let one_year = one_week * 52;
		assert_eq!(secondary_pow_ratio(one_year), 45);

		let ninety_one_weeks = one_week * 91;
		assert_eq!(secondary_pow_ratio(ninety_one_weeks - 1), 12);
		assert_eq!(secondary_pow_ratio(ninety_one_weeks), 12);
		assert_eq!(secondary_pow_ratio(ninety_one_weeks + 1), 12);

		let two_year = one_year * 2;
		assert_eq!(secondary_pow_ratio(two_year - 1), 1);
		assert_eq!(secondary_pow_ratio(two_year), 0);
		assert_eq!(secondary_pow_ratio(two_year + 1), 0);
	}

	// Tests for testnet4 chain type (covers pre and post hardfork).
	{
		global::set_local_chain_type(global::ChainTypes::Testnet);
		assert_eq!(global::is_testnet(), true);

		assert_eq!(secondary_pow_ratio(1), 90);
		assert_eq!(secondary_pow_ratio(89), 90);
		assert_eq!(secondary_pow_ratio(90), 90);
		assert_eq!(secondary_pow_ratio(91), 90);
		assert_eq!(secondary_pow_ratio(179), 90);
		assert_eq!(secondary_pow_ratio(180), 90);
		assert_eq!(secondary_pow_ratio(181), 90);

		let one_week = 60 * 24 * 7;
		assert_eq!(secondary_pow_ratio(one_week - 1), 90);
		assert_eq!(secondary_pow_ratio(one_week), 90);
		assert_eq!(secondary_pow_ratio(one_week + 1), 90);

		let two_weeks = one_week * 2;
		assert_eq!(secondary_pow_ratio(two_weeks - 1), 89);
		assert_eq!(secondary_pow_ratio(two_weeks), 89);
		assert_eq!(secondary_pow_ratio(two_weeks + 1), 89);

		let t4_fork_height = 64_000;
		assert_eq!(secondary_pow_ratio(t4_fork_height - 1), 85);
		assert_eq!(secondary_pow_ratio(t4_fork_height), 85);
		assert_eq!(secondary_pow_ratio(t4_fork_height + 1), 85);

		let one_year = one_week * 52;
		assert_eq!(secondary_pow_ratio(one_year), 45);

		let ninety_one_weeks = one_week * 91;
		assert_eq!(secondary_pow_ratio(ninety_one_weeks - 1), 12);
		assert_eq!(secondary_pow_ratio(ninety_one_weeks), 12);
		assert_eq!(secondary_pow_ratio(ninety_one_weeks + 1), 12);

		let two_year = one_year * 2;
		assert_eq!(secondary_pow_ratio(two_year - 1), 1);
		assert_eq!(secondary_pow_ratio(two_year), 0);
		assert_eq!(secondary_pow_ratio(two_year + 1), 0);
	}
}
