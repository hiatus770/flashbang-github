//! Fixed binary framing for screen/camera video paths.
//!
//! Control metadata remains protobuf on the capability control stream. Encoded
//! access units use this small header so receivers can discard stale or
//! mismatched fragments without parsing codec bytes first. The same ANFR
//! records can be carried in QUIC datagrams or in the length-prefixed reliable
//! stream framing below.

use rustc_hash::FxHashMap;
use std::time::{Duration, Instant};

use bytes::Bytes;
use thiserror::Error;

pub const FRAME_MAGIC: [u8; 4] = *b"ANFR";
pub const FRAME_VERSION: u8 = 1;
/// Wire version stamped on parity datagrams. It tags the grouping scheme —
/// v1 parity used contiguous 16-fragment groups, v2 interleaves members —
/// so receivers can apply the matching math or safely drop what they do not
/// understand. Data fragments stay on version 1; only parity moves.
pub const PARITY_WIRE_VERSION: u8 = 2;
pub const FRAME_KIND_SCREEN: u8 = 1;
pub const FRAME_KIND_CAMERA: u8 = 2;
/// XOR-parity redundancy record covering one group of data fragments of the
/// same access unit. `flags` carries the XOR of the covered fragment payload
/// lengths so a missing fragment's exact length is recoverable; the
/// `fragment_index` field carries the parity group index and
/// `fragment_count` the access unit's real fragment count. Receivers that
/// predate this kind drop it after decode, so senders can always emit parity
/// without a capability negotiation.
pub const FRAME_KIND_PARITY: u8 = 3;
/// Number of consecutive data fragments covered by one parity datagram.
/// Single-parity XOR recovers at most one lost fragment per group, which
/// matches the dominant real-world loss pattern on lightly congested links.
pub const PARITY_GROUP_FRAGMENTS: usize = 16;
pub const FLAG_KEYFRAME: u16 = 1;
pub const FLAG_CODEC_CONFIG: u16 = 1 << 1;
pub const FRAME_HEADER_BYTES: usize = 52;
// Keep headroom below the IPv6/Tailscale path MTU. Quinn and MsQuic add
// different packet protection overheads, so using the common 1,100-byte
// application datagram avoids path-MTU drops on otherwise healthy links.
pub const FRAME_DATAGRAM_BYTES: usize = 1100;
pub const FRAME_PAYLOAD_BYTES: usize = FRAME_DATAGRAM_BYTES - FRAME_HEADER_BYTES;
pub const MAX_FRAME_FRAGMENTS: usize = u16::MAX as usize;
pub const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;
/// Reliable streams are byte-oriented, so each existing ANFR packet gets a
/// little-endian length prefix. This keeps the frame record identical on the
/// wire while making arbitrary QUIC stream read boundaries harmless.
pub const STREAM_PACKET_LENGTH_BYTES: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameHeader {
    pub kind: u8,
    pub flags: u16,
    pub capability_session_id: u64,
    pub flow_id: u64,
    pub sequence: u64,
    pub fragment_index: u16,
    pub fragment_count: u16,
    pub presentation_time_us: u64,
    pub codec_config_id: u64,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FrameError {
    #[error("frame datagram is shorter than its fixed header")]
    Truncated,
    #[error("frame datagram has an invalid magic")]
    InvalidMagic,
    #[error("unsupported frame header version {0}")]
    UnsupportedVersion(u8),
    #[error("frame datagram has an invalid kind {0}")]
    InvalidKind(u8),
    #[error("frame datagram has an invalid fragment index/count")]
    InvalidFragments,
    #[error("frame exceeds the {0}-byte limit")]
    TooLarge(usize),
    #[error("datagram limit {0} cannot contain the fixed frame header and payload")]
    DatagramLimitTooSmall(usize),
}

impl FrameHeader {
    pub fn encode(self, payload: &[u8]) -> Result<Vec<u8>, FrameError> {
        if !matches!(self.kind, FRAME_KIND_SCREEN | FRAME_KIND_CAMERA) {
            return Err(FrameError::InvalidKind(self.kind));
        }
        if self.fragment_count == 0 || self.fragment_index >= self.fragment_count {
            return Err(FrameError::InvalidFragments);
        }
        if payload.len() > FRAME_PAYLOAD_BYTES {
            return Err(FrameError::TooLarge(FRAME_PAYLOAD_BYTES));
        }
        let mut bytes = Vec::with_capacity(FRAME_HEADER_BYTES + payload.len());
        self.write(&mut bytes, payload);
        Ok(bytes)
    }

    /// Appends the encoded header and payload to `out`. The header fields are
    /// validated by the caller once per access unit, so this stays on the
    /// fragmentation fast path.
    fn write(self, out: &mut Vec<u8>, payload: &[u8]) {
        // Fixed-size stack layout: the compiler turns these into plain
        // stores and the whole header lands in `out` with one memcpy.
        let mut header = [0_u8; FRAME_HEADER_BYTES];
        header[..4].copy_from_slice(&FRAME_MAGIC);
        header[4] = FRAME_VERSION;
        header[5] = self.kind;
        header[6..8].copy_from_slice(&self.flags.to_le_bytes());
        header[8..16].copy_from_slice(&self.capability_session_id.to_le_bytes());
        header[16..24].copy_from_slice(&self.flow_id.to_le_bytes());
        header[24..32].copy_from_slice(&self.sequence.to_le_bytes());
        header[32..34].copy_from_slice(&self.fragment_index.to_le_bytes());
        header[34..36].copy_from_slice(&self.fragment_count.to_le_bytes());
        header[36..44].copy_from_slice(&self.presentation_time_us.to_le_bytes());
        header[44..52].copy_from_slice(&self.codec_config_id.to_le_bytes());
        out.extend_from_slice(&header);
        out.extend_from_slice(payload);
    }

    pub fn decode(datagram: &[u8]) -> Result<(Self, &[u8]), FrameError> {
        if datagram.len() < FRAME_HEADER_BYTES {
            return Err(FrameError::Truncated);
        }
        if datagram.len() > FRAME_DATAGRAM_BYTES {
            return Err(FrameError::TooLarge(FRAME_PAYLOAD_BYTES));
        }
        if datagram[..4] != FRAME_MAGIC {
            return Err(FrameError::InvalidMagic);
        }
        if !matches!(datagram[4], 1 | 2) {
            return Err(FrameError::UnsupportedVersion(datagram[4]));
        }
        let kind = datagram[5];
        if !matches!(
            kind,
            FRAME_KIND_SCREEN | FRAME_KIND_CAMERA | FRAME_KIND_PARITY
        ) {
            return Err(FrameError::InvalidKind(kind));
        }
        let flags = u16::from_le_bytes([datagram[6], datagram[7]]);
        let capability_session_id = u64::from_le_bytes(datagram[8..16].try_into().unwrap());
        let flow_id = u64::from_le_bytes(datagram[16..24].try_into().unwrap());
        let sequence = u64::from_le_bytes(datagram[24..32].try_into().unwrap());
        let fragment_index = u16::from_le_bytes([datagram[32], datagram[33]]);
        let fragment_count = u16::from_le_bytes([datagram[34], datagram[35]]);
        if fragment_count == 0 || fragment_index >= fragment_count {
            return Err(FrameError::InvalidFragments);
        }
        let presentation_time_us = u64::from_le_bytes(datagram[36..44].try_into().unwrap());
        let codec_config_id = u64::from_le_bytes(datagram[44..52].try_into().unwrap());
        Ok((
            Self {
                kind,
                flags,
                capability_session_id,
                flow_id,
                sequence,
                fragment_index,
                fragment_count,
                presentation_time_us,
                codec_config_id,
            },
            &datagram[FRAME_HEADER_BYTES..],
        ))
    }
}

/// Split one encoded access unit into bounded QUIC datagrams.
///
/// Every fragment is a zero-copy slice of one arena allocation, so the whole
/// access unit costs a single buffer plus `count` cheap `Bytes` handles.
pub fn fragment_frame(
    kind: u8,
    capability_session_id: u64,
    flow_id: u64,
    sequence: u64,
    presentation_time_us: u64,
    codec_config_id: u64,
    frame: &[u8],
) -> Result<Vec<Bytes>, FrameError> {
    fragment_frame_with_flags(
        kind,
        0,
        capability_session_id,
        flow_id,
        sequence,
        presentation_time_us,
        codec_config_id,
        frame,
    )
}

/// Split one encoded access unit into bounded QUIC datagrams, preserving
/// access-unit flags in every fragment. Flags are repeated deliberately: a
/// receiver can make its decode decision after reassembly without depending
/// on a particular fragment arriving first.
#[allow(clippy::too_many_arguments)]
pub fn fragment_frame_with_flags(
    kind: u8,
    flags: u16,
    capability_session_id: u64,
    flow_id: u64,
    sequence: u64,
    presentation_time_us: u64,
    codec_config_id: u64,
    frame: &[u8],
) -> Result<Vec<Bytes>, FrameError> {
    fragment_frame_with_flags_and_limit(
        kind,
        flags,
        capability_session_id,
        flow_id,
        sequence,
        presentation_time_us,
        codec_config_id,
        frame,
        FRAME_DATAGRAM_BYTES,
    )
}

/// Split one access unit with a peer's application datagram limit.
///
/// The result still uses one shared arena and `Bytes` slices. This keeps the
/// negotiated-limit path allocation-equivalent to the normal sender path.
#[allow(clippy::too_many_arguments)]
pub fn fragment_frame_with_flags_and_limit(
    kind: u8,
    flags: u16,
    capability_session_id: u64,
    flow_id: u64,
    sequence: u64,
    presentation_time_us: u64,
    codec_config_id: u64,
    frame: &[u8],
    datagram_limit: usize,
) -> Result<Vec<Bytes>, FrameError> {
    if !matches!(kind, FRAME_KIND_SCREEN | FRAME_KIND_CAMERA) {
        return Err(FrameError::InvalidKind(kind));
    }
    if frame.is_empty() {
        return Err(FrameError::Truncated);
    }
    if frame.len() > MAX_FRAME_BYTES {
        return Err(FrameError::TooLarge(MAX_FRAME_BYTES));
    }
    let datagram_bytes = datagram_limit.min(FRAME_DATAGRAM_BYTES);
    let payload_bytes = datagram_bytes
        .checked_sub(FRAME_HEADER_BYTES)
        .filter(|payload_bytes| *payload_bytes > 0)
        .ok_or(FrameError::DatagramLimitTooSmall(datagram_limit))?;
    let count = frame.len().div_ceil(payload_bytes);
    if count > MAX_FRAME_FRAGMENTS {
        return Err(FrameError::TooLarge(MAX_FRAME_FRAGMENTS * payload_bytes));
    }
    let count = count as u16;
    // Pack every fragment into a single arena, then hand out zero-copy slice
    // handles. Quinn keeps each `Bytes` alive until the datagram is flushed,
    // so the arena is freed only after the last fragment leaves the queue.
    let mut arena = Vec::with_capacity(frame.len() + usize::from(count) * FRAME_HEADER_BYTES);
    let mut packets = Vec::with_capacity(usize::from(count));
    for (index, payload) in frame.chunks(payload_bytes).enumerate() {
        let start = arena.len();
        FrameHeader {
            kind,
            flags,
            capability_session_id,
            flow_id,
            sequence,
            fragment_index: index as u16,
            fragment_count: count,
            presentation_time_us,
            codec_config_id,
        }
        .write(&mut arena, payload);
        packets.push((start, arena.len()));
    }
    let arena = Bytes::from(arena);
    Ok(packets
        .into_iter()
        .map(|(start, end)| arena.slice(start..end))
        .collect())
}

/// Split one encoded access unit into datagrams plus XOR-parity redundancy.
///
/// Emits `ceil(count / PARITY_GROUP_FRAGMENTS)` parity datagrams whose
/// payloads are the bytewise XOR of each group's fragments, zero-padded to
/// `FRAME_PAYLOAD_BYTES`. Groups are interleaved — group `g` covers fragment
/// indices `g, g + num_groups, g + 2·num_groups, …` — so a burst of up to
/// `num_groups − 1` consecutive losses lands in distinct groups and every
/// loss stays single-XOR recoverable. The parity header's `flags` field
/// carries the XOR of the covered payload lengths so the one missing
/// fragment in a group can be reconstructed byte-exact, including its real
/// length. Parity datagrams are emitted after the data burst so they do not
/// interleave with media delivery. They cost roughly 1/16 of media bandwidth
/// on the lossy datagram path and are meaningless on reliable streams, so
/// callers should use this only where datagrams may be dropped.
#[allow(clippy::too_many_arguments)]
pub fn fragment_frame_with_parity(
    kind: u8,
    flags: u16,
    capability_session_id: u64,
    flow_id: u64,
    sequence: u64,
    presentation_time_us: u64,
    codec_config_id: u64,
    frame: &[u8],
) -> Result<Vec<Bytes>, FrameError> {
    let mut packets = fragment_frame_with_flags(
        kind,
        flags,
        capability_session_id,
        flow_id,
        sequence,
        presentation_time_us,
        codec_config_id,
        frame,
    )?;
    let count = packets.len() as u16;
    let num_groups = (count as usize).div_ceil(PARITY_GROUP_FRAGMENTS);
    let mut parity = Vec::with_capacity(num_groups);
    for group_index in 0..num_groups {
        let mut acc = [0_u8; FRAME_PAYLOAD_BYTES];
        let mut length_xor = 0_u16;
        for packet in packets.iter().skip(group_index).step_by(num_groups) {
            let payload = &packet[FRAME_HEADER_BYTES..];
            length_xor ^= payload.len() as u16;
            for (a, b) in acc.iter_mut().zip(payload.iter()) {
                *a ^= *b;
            }
        }
        let mut bytes = Vec::with_capacity(FRAME_DATAGRAM_BYTES);
        FrameHeader {
            kind: FRAME_KIND_PARITY,
            flags: length_xor,
            capability_session_id,
            flow_id,
            sequence,
            fragment_index: group_index as u16,
            fragment_count: count,
            presentation_time_us,
            codec_config_id,
        }
        .write(&mut bytes, &acc);
        // Parity wire version tags the grouping scheme: v1 was contiguous
        // groups, v2 interleaves members. Receivers that only know v1 reject
        // the header outright — never mis-reconstruct with the wrong scheme.
        bytes[4] = PARITY_WIRE_VERSION;
        parity.push(Bytes::from(bytes));
    }
    packets.extend(parity);
    Ok(packets)
}

/// Read the routing flow ID out of an ANFR datagram. Used by the session's
/// datagram dispatcher before per-flow validation — it deliberately skips
/// kind and fragment checks so a malformed packet still reaches the flow
/// that owns it and is rejected there with full context.
pub fn datagram_flow_id(datagram: &[u8]) -> Option<u64> {
    if datagram.len() < FRAME_HEADER_BYTES || datagram[..4] != FRAME_MAGIC {
        return None;
    }
    Some(u64::from_le_bytes(datagram[16..24].try_into().unwrap()))
}

/// Prefix one ANFR packet for a reliable QUIC stream.
pub fn encode_stream_packet(packet: &[u8]) -> Result<Vec<u8>, FrameError> {
    if packet.is_empty() || packet.len() > FRAME_DATAGRAM_BYTES {
        return Err(FrameError::TooLarge(FRAME_DATAGRAM_BYTES));
    }
    let length =
        u32::try_from(packet.len()).map_err(|_| FrameError::TooLarge(u32::MAX as usize))?;
    let mut bytes = Vec::with_capacity(STREAM_PACKET_LENGTH_BYTES + packet.len());
    bytes.extend_from_slice(&length.to_le_bytes());
    bytes.extend_from_slice(packet);
    Ok(bytes)
}

/// Interleave little-endian length prefixes with ANFR packets for a vectored
/// reliable-stream write. Each packet becomes two consecutive chunks — a
/// 4-byte length prefix and the packet itself — so callers can submit the
/// result to `write_all_chunks` without concatenating anything.
pub fn stream_chunks(packets: &[Bytes]) -> Result<Vec<Bytes>, FrameError> {
    let mut prefixes = Vec::with_capacity(packets.len() * STREAM_PACKET_LENGTH_BYTES);
    for packet in packets {
        if packet.is_empty() || packet.len() > FRAME_DATAGRAM_BYTES {
            return Err(FrameError::TooLarge(FRAME_DATAGRAM_BYTES));
        }
        prefixes.extend_from_slice(&(packet.len() as u32).to_le_bytes());
    }
    let prefixes = Bytes::from(prefixes);
    let mut chunks = Vec::with_capacity(packets.len() * 2);
    for (index, packet) in packets.iter().enumerate() {
        let start = index * STREAM_PACKET_LENGTH_BYTES;
        chunks.push(prefixes.slice(start..start + STREAM_PACKET_LENGTH_BYTES));
        chunks.push(packet.clone());
    }
    Ok(chunks)
}

/// Bounds applied while reassembling ANFR fragments. Datagrams are
/// intentionally lossy, so incomplete access units must never accumulate
/// without limit.
const PARTIAL_FRAME_TTL: Duration = Duration::from_millis(500);
const MAX_PARTIAL_FRAMES: usize = 32;

struct PartialFrame {
    created: Instant,
    fragment_count: u16,
    fragments: Vec<Option<Bytes>>,
    received: usize,
    total_bytes: usize,
}

/// One stored parity record: the XOR of a fragment group's payloads plus the
/// XOR of their payload lengths. Bounded like partial frames — parity that
/// outlives a frame's TTL is useless anyway.
struct ParityEntry {
    created: Instant,
    length_xor: u16,
    payload: Bytes,
}

/// Generous bound: a max-size frame carries ~500 parity groups and a handful
/// of frames may be in flight, so the cap stays far above realistic use while
/// still bounding memory (~8 MiB) against a stream of stray parity packets.
const MAX_PENDING_PARITIES: usize = 8192;

/// Reassembles ANFR datagrams back into complete access units.
///
/// Fragments are stored as zero-copy slices of the received datagrams, so the
/// only payload copy happens once, when the complete frame is produced. The
/// map is bounded and half-assembled frames expire quickly.
#[derive(Default)]
pub struct Reassembler {
    partial: FxHashMap<u64, PartialFrame>,
    /// Parity records indexed by (frame sequence, parity group index). They
    /// can arrive before, between, or after data fragments — datagrams are
    /// unordered — so they live in their own map rather than inside a
    /// PartialFrame that may not exist yet.
    pending_parities: FxHashMap<(u64, u16), ParityEntry>,
    /// Expiry sweeps are throttled to once per TTL: running `retain` on every
    /// datagram costs an O(map) scan for no benefit — stale entries can sit
    /// one extra interval without harm since the map is bounded anyway.
    last_sweep: Option<Instant>,
}

impl Reassembler {
    /// Feed one received datagram. Returns the complete access unit once its
    /// last fragment arrives. Datagrams for other flows, other kinds, or with
    /// inconsistent fragment counts are discarded.
    pub fn add_datagram(
        &mut self,
        datagram: &Bytes,
        kind: u8,
        capability_session_id: u64,
        flow_id: u64,
    ) -> Option<Vec<u8>> {
        let (header, _) = FrameHeader::decode(datagram).ok()?;
        if header.capability_session_id != capability_session_id || header.flow_id != flow_id {
            return None;
        }
        if header.kind == FRAME_KIND_PARITY {
            self.store_parity(header, datagram);
            return self.try_parity_recovery(header.sequence);
        }
        if header.kind != kind {
            return None;
        }
        let now = Instant::now();
        if (!self.partial.is_empty() || !self.pending_parities.is_empty())
            && self
                .last_sweep
                .is_none_or(|t| now.duration_since(t) >= PARTIAL_FRAME_TTL)
        {
            self.partial
                .retain(|_, frame| now.duration_since(frame.created) <= PARTIAL_FRAME_TTL);
            self.pending_parities
                .retain(|_, parity| now.duration_since(parity.created) <= PARTIAL_FRAME_TTL);
            self.last_sweep = Some(now);
        }
        if self.partial.len() >= MAX_PARTIAL_FRAMES
            && !self.partial.contains_key(&header.sequence)
            && let Some(oldest) = self
                .partial
                .iter()
                .min_by_key(|(_, frame)| frame.created)
                .map(|(sequence, _)| *sequence)
        {
            self.partial.remove(&oldest);
        }
        let entry = self
            .partial
            .entry(header.sequence)
            .or_insert_with(|| PartialFrame {
                created: now,
                fragment_count: header.fragment_count,
                // A frame can never legitimately exceed MAX_FRAME_BYTES, so a
                // claimed fragment count above the maximum possible can never
                // complete — cap the slot vector rather than trusting the wire.
                fragments: vec![
                    None;
                    usize::from(header.fragment_count)
                        .min(MAX_FRAME_BYTES.div_ceil(FRAME_PAYLOAD_BYTES))
                ],
                received: 0,
                total_bytes: 0,
            });
        if entry.fragment_count != header.fragment_count {
            self.partial.remove(&header.sequence);
            return None;
        }
        let index = usize::from(header.fragment_index);
        if index >= entry.fragments.len() {
            // Impossible fragment index for a capped slot vector — this frame
            // could never complete within MAX_FRAME_BYTES anyway.
            self.partial.remove(&header.sequence);
            return None;
        }
        if entry.fragments[index].is_none() {
            let payload = datagram.slice(FRAME_HEADER_BYTES..);
            entry.total_bytes += payload.len();
            if entry.total_bytes > MAX_FRAME_BYTES {
                self.partial.remove(&header.sequence);
                return None;
            }
            entry.fragments[index] = Some(payload);
            entry.received += 1;
        }
        let received = entry.received;
        let fragment_count = usize::from(entry.fragment_count);
        if received != fragment_count {
            // Parity can only help while every missing fragment could still
            // sit in a distinct group; deeper holes are guaranteed dead.
            let num_groups = entry.fragments.len().div_ceil(PARITY_GROUP_FRAGMENTS);
            if fragment_count - received <= num_groups {
                return self.try_parity_recovery(header.sequence);
            }
            return None;
        }
        let entry = self.partial.remove(&header.sequence)?;
        let mut frame = Vec::with_capacity(entry.total_bytes);
        for fragment in entry.fragments {
            frame.extend_from_slice(&fragment?);
        }
        Some(frame)
    }

    /// Store one parity datagram keyed by (frame sequence, group index).
    /// Parity payloads are fixed-width; a short or absent payload can never
    /// reconstruct anything, so it is dropped. Only `PARITY_WIRE_VERSION`
    /// records are applied: builds between the first contiguous-parity
    /// implementation and the interleaved rewrite both stamped `1`, so a
    /// v1 record's grouping is unknowable and reconstructing from it could
    /// yield garbage bytes — dropping costs only the recovery itself.
    fn store_parity(&mut self, header: FrameHeader, datagram: &Bytes) {
        let payload = datagram.slice(FRAME_HEADER_BYTES..);
        if datagram[4] != PARITY_WIRE_VERSION
            || payload.len() != FRAME_PAYLOAD_BYTES
            || self.pending_parities.len() >= MAX_PENDING_PARITIES
        {
            return;
        }
        self.pending_parities.insert(
            (header.sequence, header.fragment_index),
            ParityEntry {
                created: Instant::now(),
                length_xor: header.flags,
                payload,
            },
        );
    }

    /// Reconstruct a frame whose missing fragments are each their parity
    /// group's only hole. XOR parity recovers at most one loss per group —
    /// but groups stripe fragments `i, i + num_groups, …`, so up to
    /// `num_groups` losses stay recoverable as long as no group is holed
    /// twice. The scan only runs when `missing <= num_groups`, which is the
    /// precondition for every hole to sit in a distinct group.
    fn try_parity_recovery(&mut self, sequence: u64) -> Option<Vec<u8>> {
        loop {
            let candidate = {
                let entry = self.partial.get(&sequence)?;
                let num_groups = entry.fragments.len().div_ceil(PARITY_GROUP_FRAGMENTS);
                if entry.fragments.len() - entry.received > num_groups {
                    return None;
                }
                let mut holes = vec![0usize; num_groups];
                for (index, slot) in entry.fragments.iter().enumerate() {
                    if slot.is_none() {
                        holes[index % num_groups] += 1;
                    }
                }
                entry
                    .fragments
                    .iter()
                    .enumerate()
                    .find_map(|(index, slot)| {
                        if slot.is_some() {
                            return None;
                        }
                        let group = index % num_groups;
                        if holes[group] == 1
                            && self
                                .pending_parities
                                .contains_key(&(sequence, group as u16))
                        {
                            return Some((index, group));
                        }
                        None
                    })
            };
            let (missing, group) = candidate?;
            let entry = self.partial.get(&sequence)?;
            let num_groups = entry.fragments.len().div_ceil(PARITY_GROUP_FRAGMENTS);
            let parity = self.pending_parities.get(&(sequence, group as u16))?;
            let mut acc = [0_u8; FRAME_PAYLOAD_BYTES];
            acc.copy_from_slice(&parity.payload);
            let mut length_xor = parity.length_xor;
            for fragment in entry
                .fragments
                .iter()
                .skip(group)
                .step_by(num_groups)
                .flatten()
            {
                length_xor ^= fragment.len() as u16;
                for (a, b) in acc.iter_mut().zip(fragment.iter()) {
                    *a ^= *b;
                }
            }
            let missing_len = usize::from(length_xor);
            if missing_len == 0 || missing_len > FRAME_PAYLOAD_BYTES {
                return None;
            }
            let recovered = Bytes::copy_from_slice(&acc[..missing_len]);
            let entry = self.partial.get_mut(&sequence)?;
            entry.total_bytes += missing_len;
            if entry.total_bytes > MAX_FRAME_BYTES {
                self.partial.remove(&sequence);
                return None;
            }
            entry.fragments[missing] = Some(recovered);
            entry.received += 1;
            if entry.received == usize::from(entry.fragment_count) {
                let entry = self.partial.remove(&sequence)?;
                let mut frame = Vec::with_capacity(entry.total_bytes);
                for fragment in entry.fragments {
                    frame.extend_from_slice(&fragment?);
                }
                return Some(frame);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[allow(clippy::too_many_arguments)]
    fn wire_packet(
        kind: u8,
        flags: u16,
        capability_session_id: u64,
        flow_id: u64,
        sequence: u64,
        fragment_index: u16,
        fragment_count: u16,
        presentation_time_us: u64,
        codec_config_id: u64,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(FRAME_HEADER_BYTES + payload.len());
        bytes.extend_from_slice(b"ANFR");
        bytes.push(1);
        bytes.push(kind);
        bytes.extend_from_slice(&flags.to_le_bytes());
        bytes.extend_from_slice(&capability_session_id.to_le_bytes());
        bytes.extend_from_slice(&flow_id.to_le_bytes());
        bytes.extend_from_slice(&sequence.to_le_bytes());
        bytes.extend_from_slice(&fragment_index.to_le_bytes());
        bytes.extend_from_slice(&fragment_count.to_le_bytes());
        bytes.extend_from_slice(&presentation_time_us.to_le_bytes());
        bytes.extend_from_slice(&codec_config_id.to_le_bytes());
        bytes.extend_from_slice(payload);
        bytes
    }

    fn valid_packet() -> Vec<u8> {
        FrameHeader {
            kind: FRAME_KIND_SCREEN,
            flags: 0,
            capability_session_id: 1,
            flow_id: 2,
            sequence: 3,
            fragment_index: 0,
            fragment_count: 1,
            presentation_time_us: 4,
            codec_config_id: 5,
        }
        .encode(&[0xca, 0xfe])
        .unwrap()
    }

    #[test]
    fn decode_rejects_invalid_magic() {
        let mut packet = valid_packet();
        packet[..4].copy_from_slice(b"NOPE");
        assert_eq!(FrameHeader::decode(&packet), Err(FrameError::InvalidMagic),);
    }

    #[test]
    fn decode_rejects_supported_version() {
        // Version 2 is the parity grouping-scheme tag; anything past it is
        // genuinely unknown and must still be rejected.
        let mut packet = valid_packet();
        packet[4] = 3;
        assert_eq!(
            FrameHeader::decode(&packet),
            Err(FrameError::UnsupportedVersion(3)),
        );
        for version in [1u8, PARITY_WIRE_VERSION] {
            packet[4] = version;
            assert!(FrameHeader::decode(&packet).is_ok());
        }
    }

    #[test]
    fn decode_rejects_fragment_index_equal_to_count() {
        let mut packet = valid_packet();
        packet[32..34].copy_from_slice(&3u16.to_le_bytes());
        packet[34..36].copy_from_slice(&3u16.to_le_bytes());

        assert_eq!(
            FrameHeader::decode(&packet),
            Err(FrameError::InvalidFragments),
        );
    }

    #[test]
    fn decode_rejects_a_payload_larger_than_the_declared_datagram_limit() {
        let header = FrameHeader {
            kind: FRAME_KIND_SCREEN,
            flags: 0,
            capability_session_id: 1,
            flow_id: 2,
            sequence: 3,
            fragment_index: 0,
            fragment_count: 1,
            presentation_time_us: 4,
            codec_config_id: 5,
        };
        let packet = header.encode(&vec![0; FRAME_PAYLOAD_BYTES]).unwrap();
        let mut oversized = packet;
        oversized.push(0);

        assert_eq!(
            FrameHeader::decode(&oversized),
            Err(FrameError::TooLarge(FRAME_PAYLOAD_BYTES)),
        );
    }

    #[test]
    fn header_round_trip_preserves_all_fields() {
        let header = FrameHeader {
            kind: FRAME_KIND_SCREEN,
            flags: 3,
            capability_session_id: 7,
            flow_id: 11,
            sequence: 13,
            fragment_index: 1,
            fragment_count: 2,
            presentation_time_us: 17,
            codec_config_id: 19,
        };
        let encoded = header.encode(&[1, 2, 3]).unwrap();
        let (decoded, payload) = FrameHeader::decode(&encoded).unwrap();
        assert_eq!(decoded, header);
        assert_eq!(payload, &[1, 2, 3]);
    }

    proptest! {
        #[test]
        fn header_round_trip_preserves_any_valid_fields(
            kind in prop_oneof![
                 Just(FRAME_KIND_SCREEN),
                 Just(FRAME_KIND_CAMERA),
             ],
             flags in any::<u16>(),
             capability_session_id in any::<u64>(),
             flow_id in any::<u64>(),
             sequence in any::<u64>(),
             fragment_count in 1u16..=u16::MAX,
             raw_fragment_index in any::<u16>(),
             presentation_time_us in any::<u64>(),
             codec_config_id in any::<u64>(),
             payload in prop::collection::vec(any::<u8>(), 0..=FRAME_PAYLOAD_BYTES),
        ){
            let header = FrameHeader {
                kind,
                flags,
                capability_session_id,
                flow_id,
                sequence,
                fragment_index: raw_fragment_index % fragment_count,
                fragment_count,
                presentation_time_us,
                codec_config_id,
            };

            let encoded = header.encode(&payload).expect("generated header is valid");
            let (decoded, decoded_payload) = FrameHeader::decode(&encoded).expect("encoded header must decode");

            prop_assert_eq!(decoded, header);
            prop_assert_eq!(decoded_payload, payload.as_slice());
            prop_assert!(encoded.len() <= FRAME_DATAGRAM_BYTES);

        }

        #[test]
        fn decode_rejects_every_truncated_header(
            length in 0usize..FRAME_HEADER_BYTES,
        ) {
            let packet = valid_packet();
            prop_assert_eq!(
                FrameHeader::decode(&packet[..length]),
                Err(FrameError::Truncated),
            )
        }

        #[test]
        fn decode_matches_independent_anfr_wire_format(
                 kind in prop_oneof![
                     Just(FRAME_KIND_SCREEN),
                     Just(FRAME_KIND_CAMERA),
                 ],
                 flags in any::<u16>(),
                 capability_session_id in any::<u64>(),
                 flow_id in any::<u64>(),
                 sequence in any::<u64>(),
                 fragment_count in 1u16..=u16::MAX,
                 raw_fragment_index in any::<u16>(),
                 presentation_time_us in any::<u64>(),
                 codec_config_id in any::<u64>(),
                 payload in prop::collection::vec(any::<u8>(), 0..=FRAME_PAYLOAD_BYTES),
             ) {
                 let fragment_index = raw_fragment_index % fragment_count;

                 let packet = wire_packet(
                     kind,
                     flags,
                     capability_session_id,
                     flow_id,
                     sequence,
                     fragment_index,
                     fragment_count,
                     presentation_time_us,
                     codec_config_id,
                     &payload,
                 );

                 let (header, decoded_payload) = FrameHeader::decode(&packet).unwrap();

                 prop_assert_eq!(header.kind, kind);
                 prop_assert_eq!(header.flags, flags);
                 prop_assert_eq!(header.capability_session_id, capability_session_id);
                 prop_assert_eq!(header.flow_id, flow_id);
                 prop_assert_eq!(header.sequence, sequence);
                 prop_assert_eq!(header.fragment_index, fragment_index);
                 prop_assert_eq!(header.fragment_count, fragment_count);
                 prop_assert_eq!(header.presentation_time_us, presentation_time_us);
                 prop_assert_eq!(header.codec_config_id, codec_config_id);
                 prop_assert_eq!(decoded_payload, payload.as_slice());
             }

        #[test]
        fn fragmentation_matches_independent_payload_chunks(
            kind in prop_oneof![Just(FRAME_KIND_SCREEN), Just(FRAME_KIND_CAMERA)],
            flags in any::<u16>(),
            capability_session_id in any::<u64>(),
            flow_id in any::<u64>(),
            sequence in any::<u64>(),
            presentation_time_us in any::<u64>(),
            codec_config_id in any::<u64>(),
            payload in prop::collection::vec(
                any::<u8>(),
                1..=(FRAME_PAYLOAD_BYTES * 4 + 1),
            ),
        ) {
            let packets = fragment_frame_with_flags(
                kind,
                flags,
                capability_session_id,
                flow_id,
                sequence,
                presentation_time_us,
                codec_config_id,
                &payload,
            )
            .unwrap();
            let expected_chunks = payload.chunks(FRAME_PAYLOAD_BYTES).collect::<Vec<_>>();
            let expected_fragment_count = expected_chunks.len() as u16;

            prop_assert_eq!(packets.len(), expected_chunks.len());
            for (index, (packet, expected_payload)) in packets.iter().zip(expected_chunks).enumerate() {
                let (header, decoded_payload) = FrameHeader::decode(packet).unwrap();
                prop_assert!(packet.len() <= FRAME_DATAGRAM_BYTES);
                prop_assert_eq!(header.kind, kind);
                prop_assert_eq!(header.flags, flags);
                prop_assert_eq!(header.capability_session_id, capability_session_id);
                prop_assert_eq!(header.flow_id, flow_id);
                prop_assert_eq!(header.sequence, sequence);
                prop_assert_eq!(header.fragment_index, index as u16);
                prop_assert_eq!(header.fragment_count, expected_fragment_count);
                prop_assert_eq!(header.presentation_time_us, presentation_time_us);
                prop_assert_eq!(header.codec_config_id, codec_config_id);
                prop_assert_eq!(decoded_payload, expected_payload);
            }
        }
    }

    #[test]
    fn fragmentation_reassembles_in_order() {
        let frame = vec![42u8; FRAME_PAYLOAD_BYTES * 2 + 7];
        let packets = fragment_frame(FRAME_KIND_CAMERA, 1, 2, 3, 4, 5, &frame).unwrap();
        assert_eq!(packets.len(), 3);
        let mut rebuilt = Vec::new();
        for packet in packets {
            let (header, payload) = FrameHeader::decode(&packet).unwrap();
            assert_eq!(header.fragment_count, 3);
            rebuilt.extend_from_slice(payload);
        }
        assert_eq!(rebuilt, frame);
    }

    #[test]
    fn negotiated_datagram_limit_bounds_every_packet_and_preserves_frame() {
        for limit in [53, 54, 127, 128, 255, 256, 1_085, 1_097, 1_100, 1_200] {
            let payload_limit = limit.min(FRAME_DATAGRAM_BYTES) - FRAME_HEADER_BYTES;
            for frame_len in [
                1,
                payload_limit,
                payload_limit + 1,
                payload_limit * 2,
                payload_limit * 2 + 1,
            ] {
                let frame = (0..frame_len)
                    .map(|index| (index % 251) as u8)
                    .collect::<Vec<_>>();
                let packets = fragment_frame_with_flags_and_limit(
                    FRAME_KIND_SCREEN,
                    FLAG_KEYFRAME,
                    1,
                    2,
                    3,
                    4,
                    5,
                    &frame,
                    limit,
                )
                .unwrap();

                let expected_count = (frame_len + payload_limit - 1) / payload_limit;
                assert_eq!(
                    packets.len(),
                    expected_count,
                    "limit={limit} frame={frame_len}"
                );
                assert!(packets.iter().all(|packet| packet.len() <= limit));
                let rebuilt = packets
                    .iter()
                    .flat_map(|packet| &packet[FRAME_HEADER_BYTES..])
                    .copied()
                    .collect::<Vec<_>>();
                assert_eq!(rebuilt, frame, "limit={limit} frame={frame_len}");
            }
        }
    }

    #[test]
    fn negotiated_datagram_limit_requires_room_for_payload() {
        for limit in [0, FRAME_HEADER_BYTES - 1, FRAME_HEADER_BYTES] {
            assert_eq!(
                fragment_frame_with_flags_and_limit(
                    FRAME_KIND_SCREEN,
                    0,
                    1,
                    2,
                    3,
                    4,
                    5,
                    &[9],
                    limit,
                ),
                Err(FrameError::DatagramLimitTooSmall(limit))
            );
        }

        let packet = fragment_frame_with_flags_and_limit(
            FRAME_KIND_SCREEN,
            0,
            1,
            2,
            3,
            4,
            5,
            &[9],
            FRAME_HEADER_BYTES + 1,
        )
        .unwrap();
        assert_eq!(packet[0].len(), FRAME_HEADER_BYTES + 1);
    }

    #[test]
    fn stream_packet_prefixes_existing_frame_record() {
        let packet = vec![7u8; FRAME_DATAGRAM_BYTES];
        let encoded = encode_stream_packet(&packet).unwrap();
        assert_eq!(
            u32::from_le_bytes(encoded[..4].try_into().unwrap()) as usize,
            packet.len()
        );
        assert_eq!(&encoded[4..], packet.as_slice());
    }

    #[test]
    fn flagged_fragmentation_repeats_flags_on_every_fragment() {
        let packets = fragment_frame_with_flags(
            FRAME_KIND_SCREEN,
            FLAG_KEYFRAME,
            1,
            2,
            3,
            4,
            5,
            &vec![7u8; FRAME_PAYLOAD_BYTES * 2 + 1],
        )
        .unwrap();
        assert!(
            packets
                .iter()
                .all(|packet| { FrameHeader::decode(packet).unwrap().0.flags == FLAG_KEYFRAME })
        );
    }

    #[test]
    fn malformed_header_is_rejected() {
        assert_eq!(FrameHeader::decode(b"ANFR"), Err(FrameError::Truncated));
        let mut packet = vec![0u8; FRAME_HEADER_BYTES];
        packet[..4].copy_from_slice(b"NOPE");
        assert_eq!(FrameHeader::decode(&packet), Err(FrameError::InvalidMagic));
    }

    #[test]
    fn stream_chunks_interleave_prefixes_without_copying_payloads() {
        let packets = fragment_frame(FRAME_KIND_SCREEN, 9, 4, 77, 123, 1, &[7; 3000]).unwrap();
        let chunks = stream_chunks(&packets).unwrap();
        assert_eq!(chunks.len(), packets.len() * 2);
        for (index, packet) in packets.iter().enumerate() {
            let prefix = &chunks[index * 2];
            assert_eq!(prefix.len(), STREAM_PACKET_LENGTH_BYTES);
            assert_eq!(
                u32::from_le_bytes(prefix[..].try_into().unwrap()) as usize,
                packet.len()
            );
            // The payload chunk must be the same arena storage, not a copy.
            assert!(std::ptr::eq(
                chunks[index * 2 + 1].as_ptr(),
                packet.as_ptr()
            ));
        }
        let mut stream = Vec::new();
        for chunk in &chunks {
            stream.extend_from_slice(chunk);
        }
        let mut offset = 0;
        let mut reassembled = Vec::new();
        while offset < stream.len() {
            let end = offset + STREAM_PACKET_LENGTH_BYTES;
            let length = u32::from_le_bytes(stream[offset..end].try_into().unwrap()) as usize;
            let (header, payload) = FrameHeader::decode(&stream[end..end + length]).unwrap();
            assert_eq!(header.sequence, 77);
            reassembled.extend_from_slice(payload);
            offset = end + length;
        }
        assert_eq!(reassembled, vec![7u8; 3000]);
    }

    #[test]
    fn reassembler_reassembles_out_of_order_and_filters_flow() {
        let payload: Vec<u8> = (0..FRAME_PAYLOAD_BYTES * 2 + 17)
            .map(|index| (index % 251) as u8)
            .collect();
        let packets = fragment_frame(FRAME_KIND_CAMERA, 9, 4, 77, 123, 1, &payload).unwrap();
        let mut reassembler = Reassembler::default();
        // Wrong flow id, duplicate fragment, then out-of-order completion.
        assert!(
            reassembler
                .add_datagram(&packets[0], FRAME_KIND_CAMERA, 9, 999)
                .is_none()
        );
        assert!(
            reassembler
                .add_datagram(&packets[2], FRAME_KIND_CAMERA, 9, 4)
                .is_none()
        );
        assert!(
            reassembler
                .add_datagram(&packets[2], FRAME_KIND_CAMERA, 9, 4)
                .is_none()
        );
        assert!(
            reassembler
                .add_datagram(&packets[1], FRAME_KIND_CAMERA, 9, 4)
                .is_none()
        );
        let rebuilt = reassembler
            .add_datagram(&packets[0], FRAME_KIND_CAMERA, 9, 4)
            .unwrap();
        assert_eq!(rebuilt, payload);
    }

    #[test]
    fn reassembler_drops_foreign_kinds_and_sessions() {
        let packets = fragment_frame(FRAME_KIND_SCREEN, 1, 2, 3, 0, 0, &[1, 2, 3]).unwrap();
        let mut reassembler = Reassembler::default();
        assert!(
            reassembler
                .add_datagram(&packets[0], FRAME_KIND_CAMERA, 1, 2)
                .is_none()
        );
        assert!(
            reassembler
                .add_datagram(&packets[0], FRAME_KIND_SCREEN, 2, 2)
                .is_none()
        );
        // A malformed datagram never reaches the map at all.
        assert!(
            reassembler
                .add_datagram(&Bytes::from_static(b"ANFR"), FRAME_KIND_SCREEN, 1, 2)
                .is_none()
        );
        // But a correct packet still completes.
        assert_eq!(
            reassembler.add_datagram(&packets[0], FRAME_KIND_SCREEN, 1, 2),
            Some(vec![1, 2, 3])
        );
    }

    #[test]
    fn parity_fragmentation_appends_one_parity_per_group() {
        // 40 fragments -> groups of 16 + 16 + 8 -> 3 parity datagrams.
        let frame = vec![9u8; FRAME_PAYLOAD_BYTES * 40];
        let packets =
            fragment_frame_with_parity(FRAME_KIND_SCREEN, 0, 1, 2, 3, 4, 5, &frame).unwrap();
        assert_eq!(packets.len(), 43);
        for (index, packet) in packets.iter().enumerate().skip(40) {
            let (header, payload) = FrameHeader::decode(packet).unwrap();
            assert_eq!(header.kind, FRAME_KIND_PARITY);
            assert_eq!(header.fragment_index as usize, index - 40);
            assert_eq!(header.fragment_count, 40);
            assert_eq!(header.sequence, 3);
            assert_eq!(payload.len(), FRAME_PAYLOAD_BYTES);
        }
    }

    #[test]
    fn parity_recovers_single_lost_fragment() {
        let frame: Vec<u8> = (0..FRAME_PAYLOAD_BYTES * 40)
            .map(|index| (index % 251) as u8)
            .collect();
        let packets =
            fragment_frame_with_parity(FRAME_KIND_SCREEN, 0, 1, 2, 3, 4, 5, &frame).unwrap();
        // Drop fragment 7 (group 0); every other packet including parity arrives.
        let mut reassembler = Reassembler::default();
        let mut rebuilt = None;
        for (index, packet) in packets.iter().enumerate() {
            if index == 7 {
                continue;
            }
            if let Some(frame) = reassembler.add_datagram(packet, FRAME_KIND_SCREEN, 1, 2) {
                rebuilt = Some(frame);
            }
        }
        assert_eq!(rebuilt.unwrap(), frame);
    }

    #[test]
    fn parity_arriving_before_data_still_recovers() {
        let frame: Vec<u8> = (0..FRAME_PAYLOAD_BYTES * 20)
            .map(|index| (index % 199) as u8)
            .collect();
        let packets =
            fragment_frame_with_parity(FRAME_KIND_SCREEN, 0, 1, 2, 3, 4, 5, &frame).unwrap();
        let mut reassembler = Reassembler::default();
        // Parity lands first (unordered datagrams), fragment 2 is lost.
        let mut rebuilt = None;
        for packet in packets.iter().skip(20) {
            assert!(
                reassembler
                    .add_datagram(packet, FRAME_KIND_SCREEN, 1, 2)
                    .is_none()
            );
        }
        for (index, packet) in packets.iter().enumerate().take(20) {
            if index == 2 {
                continue;
            }
            if let Some(frame) = reassembler.add_datagram(packet, FRAME_KIND_SCREEN, 1, 2) {
                rebuilt = Some(frame);
            }
        }
        assert_eq!(rebuilt.unwrap(), frame);
    }

    #[test]
    fn parity_recovers_lost_short_final_fragment() {
        // 17 fragments with a short tail: loss in the last group exercises the
        // length-XOR recovery path.
        let frame: Vec<u8> = (0..FRAME_PAYLOAD_BYTES * 16 + 137)
            .map(|index| (index % 241) as u8)
            .collect();
        let packets =
            fragment_frame_with_parity(FRAME_KIND_SCREEN, 0, 1, 2, 3, 4, 5, &frame).unwrap();
        let mut reassembler = Reassembler::default();
        let mut rebuilt = None;
        for (index, packet) in packets.iter().enumerate() {
            if index == 16 {
                continue;
            }
            if let Some(frame) = reassembler.add_datagram(packet, FRAME_KIND_SCREEN, 1, 2) {
                rebuilt = Some(frame);
            }
        }
        assert_eq!(rebuilt.unwrap(), frame);
    }

    #[test]
    fn parity_recovers_burst_loss_across_interleaved_groups() {
        // Three consecutive fragment losses land in three different
        // interleaved groups — each is its group's only hole and recovers.
        let frame: Vec<u8> = (0..FRAME_PAYLOAD_BYTES * 40)
            .map(|index| (index % 211) as u8)
            .collect();
        let packets =
            fragment_frame_with_parity(FRAME_KIND_SCREEN, 0, 1, 2, 3, 4, 5, &frame).unwrap();
        let mut reassembler = Reassembler::default();
        let mut rebuilt = None;
        for (index, packet) in packets.iter().enumerate() {
            if (10..13).contains(&index) {
                continue;
            }
            if let Some(frame) = reassembler.add_datagram(packet, FRAME_KIND_SCREEN, 1, 2) {
                rebuilt = Some(frame);
            }
        }
        assert_eq!(rebuilt.as_deref(), Some(frame.as_slice()));
    }

    #[test]
    fn parity_cannot_recover_two_losses_in_one_group() {
        // Interleaved groups for a 40-fragment frame are indices mod 3, so
        // fragments 3 and 6 share a group — two holes defeat single-XOR.
        let frame = vec![5u8; FRAME_PAYLOAD_BYTES * 40];
        let packets =
            fragment_frame_with_parity(FRAME_KIND_SCREEN, 0, 1, 2, 3, 4, 5, &frame).unwrap();
        let mut reassembler = Reassembler::default();
        for (index, packet) in packets.iter().enumerate() {
            if index == 3 || index == 6 {
                continue;
            }
            assert!(
                reassembler
                    .add_datagram(packet, FRAME_KIND_SCREEN, 1, 2)
                    .is_none()
            );
        }
    }

    #[test]
    fn parity_is_ignored_when_nothing_is_lost() {
        let frame: Vec<u8> = (0..FRAME_PAYLOAD_BYTES * 18)
            .map(|index| (index % 211) as u8)
            .collect();
        let packets =
            fragment_frame_with_parity(FRAME_KIND_SCREEN, 0, 1, 2, 3, 4, 5, &frame).unwrap();
        let mut reassembler = Reassembler::default();
        let mut rebuilt = None;
        for packet in packets.iter() {
            if let Some(frame) = reassembler.add_datagram(packet, FRAME_KIND_SCREEN, 1, 2) {
                rebuilt = Some(frame);
            }
        }
        assert_eq!(rebuilt.unwrap(), frame);
    }

    #[test]
    fn parity_with_legacy_v1_wire_tag_is_ignored() {
        // Builds between the first contiguous-parity implementation and the
        // interleaved rewrite both stamped version 1, so a v1 record's
        // grouping is unknowable. Applying it risks reconstructing garbage —
        // the record must be dropped even when it could have helped.
        let frame: Vec<u8> = (0..FRAME_PAYLOAD_BYTES * 18)
            .map(|index| (index % 197) as u8)
            .collect();
        let mut packets =
            fragment_frame_with_parity(FRAME_KIND_SCREEN, 0, 1, 2, 3, 4, 5, &frame).unwrap();
        for packet in packets.iter_mut().skip(18) {
            let mut downgraded = packet.to_vec();
            downgraded[4] = 1;
            *packet = Bytes::from(downgraded);
        }
        let mut reassembler = Reassembler::default();
        for (index, packet) in packets.iter().enumerate() {
            if index == 1 {
                continue;
            }
            assert!(
                reassembler
                    .add_datagram(packet, FRAME_KIND_SCREEN, 1, 2)
                    .is_none()
            );
        }
        assert!(reassembler.pending_parities.is_empty());
    }

    #[test]
    fn parity_for_another_flow_is_ignored() {
        let frame = vec![8u8; FRAME_PAYLOAD_BYTES * 20];
        let packets =
            fragment_frame_with_parity(FRAME_KIND_SCREEN, 0, 1, 2, 3, 4, 5, &frame).unwrap();
        let mut reassembler = Reassembler::default();
        for packet in packets.iter().skip(20) {
            assert!(
                reassembler
                    .add_datagram(packet, FRAME_KIND_SCREEN, 1, 99)
                    .is_none()
            );
        }
        assert!(reassembler.pending_parities.is_empty());
    }
}
