//! Microbenchmarks for the ANFR frame path: fragmentation, header
//! encode/decode, reassembly, and reliable-stream packet framing. These cover
//! the per-frame work that runs at video rate on both peers.

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

use anchor_sdk::video_frame::{self, FrameHeader};

/// Encoded-access-unit sizes representative of the screen pipeline: a small
/// predictive frame, a typical P-frame, a scene-change IDR, and a large IDR.
const FRAME_SIZES: &[usize] = &[4 * 1024, 32 * 1024, 256 * 1024, 1024 * 1024];

fn sample_frame(len: usize) -> Vec<u8> {
    (0..len).map(|index| (index % 251) as u8).collect()
}

fn bench_fragment(c: &mut Criterion) {
    let mut group = c.benchmark_group("fragment_frame");
    for size in FRAME_SIZES {
        let frame = sample_frame(*size);
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::new("arena_bytes", size), &frame, |b, frame| {
            b.iter(|| {
                video_frame::fragment_frame_with_flags(
                    video_frame::FRAME_KIND_SCREEN,
                    0,
                    1,
                    2,
                    3,
                    4,
                    0,
                    frame,
                )
                .unwrap()
            })
        });
        group.bench_with_input(
            BenchmarkId::new("arena_plus_parity", size),
            &frame,
            |b, frame| {
                b.iter(|| {
                    video_frame::fragment_frame_with_parity(
                        video_frame::FRAME_KIND_SCREEN,
                        0,
                        1,
                        2,
                        3,
                        4,
                        0,
                        frame,
                    )
                    .unwrap()
                })
            },
        );
        // Reference: the previous per-fragment `Vec<u8>` allocation scheme,
        // reproduced here so both strategies are measured in the same run.
        group.bench_with_input(
            BenchmarkId::new("vec_per_fragment", size),
            &frame,
            |b, frame| {
                b.iter(|| {
                    let count = frame.len().div_ceil(video_frame::FRAME_PAYLOAD_BYTES) as u16;
                    frame
                        .chunks(video_frame::FRAME_PAYLOAD_BYTES)
                        .enumerate()
                        .map(|(index, payload)| {
                            FrameHeader {
                                kind: video_frame::FRAME_KIND_SCREEN,
                                flags: 0,
                                capability_session_id: 1,
                                flow_id: 2,
                                sequence: 3,
                                fragment_index: index as u16,
                                fragment_count: count,
                                presentation_time_us: 4,
                                codec_config_id: 0,
                            }
                            .encode(payload)
                            .unwrap()
                        })
                        .collect::<Vec<Vec<u8>>>()
                })
            },
        );
    }
    group.finish();
}

fn bench_header_codec(c: &mut Criterion) {
    let payload = sample_frame(video_frame::FRAME_PAYLOAD_BYTES);
    let header = FrameHeader {
        kind: video_frame::FRAME_KIND_SCREEN,
        flags: 0,
        capability_session_id: 1,
        flow_id: 2,
        sequence: 3,
        fragment_index: 0,
        fragment_count: 1,
        presentation_time_us: 4,
        codec_config_id: 0,
    };
    let packet = header.encode(&payload).unwrap();

    let mut group = c.benchmark_group("frame_header");
    group.throughput(Throughput::Bytes(packet.len() as u64));
    group.bench_function("encode", |b| b.iter(|| header.encode(&payload).unwrap()));
    group.bench_function("decode", |b| {
        b.iter(|| FrameHeader::decode(std::hint::black_box(&packet)).unwrap())
    });
    group.finish();
}

fn bench_reassemble(c: &mut Criterion) {
    let mut group = c.benchmark_group("reassemble_frame");
    for size in FRAME_SIZES {
        let frame = sample_frame(*size);
        let packets = video_frame::fragment_frame_with_flags(
            video_frame::FRAME_KIND_CAMERA,
            0,
            9,
            4,
            77,
            123,
            1,
            &frame,
        )
        .unwrap();
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::new("add", size), &packets, |b, packets| {
            b.iter(|| {
                let mut assembler = video_frame::Reassembler::default();
                let mut out = None;
                for packet in packets.iter() {
                    out = assembler.add_datagram(packet, video_frame::FRAME_KIND_CAMERA, 9, 4);
                }
                std::hint::black_box(out)
            })
        });
        // Reference: the previous per-fragment `to_vec` copy scheme.
        group.bench_with_input(
            BenchmarkId::new("vec_per_fragment", size),
            &packets,
            |b, packets| {
                b.iter(|| {
                    let mut fragments: Vec<Option<Vec<u8>>> = vec![None; packets.len()];
                    for packet in packets.iter() {
                        let (header, payload) = FrameHeader::decode(packet).unwrap();
                        let index = usize::from(header.fragment_index);
                        if fragments[index].is_none() {
                            fragments[index] = Some(payload.to_vec());
                        }
                    }
                    let mut frame = Vec::new();
                    for fragment in fragments.iter().flatten() {
                        frame.extend_from_slice(fragment);
                    }
                    std::hint::black_box(frame)
                })
            },
        );
    }
    group.finish();
}

fn bench_stream_packet(c: &mut Criterion) {
    let payload = sample_frame(video_frame::FRAME_PAYLOAD_BYTES);
    let header = FrameHeader {
        kind: video_frame::FRAME_KIND_SCREEN,
        flags: 0,
        capability_session_id: 1,
        flow_id: 2,
        sequence: 3,
        fragment_index: 0,
        fragment_count: 1,
        presentation_time_us: 4,
        codec_config_id: 0,
    };
    let packet = header.encode(&payload).unwrap();
    c.bench_function("encode_stream_packet", |b| {
        b.iter(|| video_frame::encode_stream_packet(std::hint::black_box(&packet)).unwrap())
    });
}

criterion_group!(
    benches,
    bench_fragment,
    bench_header_codec,
    bench_reassemble,
    bench_stream_packet
);
criterion_main!(benches);
