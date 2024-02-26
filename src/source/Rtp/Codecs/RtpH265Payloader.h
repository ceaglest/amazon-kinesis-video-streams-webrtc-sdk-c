/*******************************************
H265 RTP Payloader include file
*******************************************/
#ifndef __KINESIS_VIDEO_WEBRTC_CLIENT_RTPH265PAYLOADER_H
#define __KINESIS_VIDEO_WEBRTC_CLIENT_RTPH265PAYLOADER_H

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#define H265_NALU_HEADER_SIZE                           (UINT8) 2
#define H265_NALU_HEADER_NAL_UNIT_TYPE_MASK             (UINT8) 0x7E
#define H265_NALU_HEADER_NUH_LAYER_ID_MASK              (UINT16) 0x01F8
#define H265_NALU_HEADER_NUH_TEMPORAL_ID_PLUS1_MASK     (UINT16) 0x0007

#define H265_RTP_PAYLOAD_HEADER_SIZE        2
#define H265_RTP_FU_HEADER_SIZE             1
#define H265_RTP_FU_HEADER_FU_TYPE_BITS     6
#define H265_RTP_FU_PAYLOAD_HEADER_TYPE     (UINT8) 49

/*
 * Payload Structures
 * ------------------
 *
 * Four different payload structures are defined in rfc7798 section 4.4.
 * Ref: https://datatracker.ietf.org/doc/html/rfc7798#section-4.4
 *
 * 1. Single NAL unit packet
 * -------------------------
 *
 * Convey a single NALU via a single RTP packet smaller than the MTU.
 *
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |           PayloadHdr          |      DONL (conditional)       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * |                  NAL unit payload data                        |
 * |                                                               |
 * |                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                               :...OPTIONAL RTP padding        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * 2. Aggregation Packets (APs)
 * ----------------------------
 *
 * TODO - An AP aggregates NAL units within one access unit.
 *
 * Useful to reduce the packet overhead required to send IDR AUs with in-band
 * parameter sets (SPS, PPS, VPS). The parameter sets must be repeated in-band
 * with each IDR if they are not signaled out of band in the SDP.
 *
 * 3. Fragmentation Units (FUs)
 * ----------------------------
 *
 * Convey a single NALU via multiple RTP packets across MTU boundaries.
 *
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |    PayloadHdr (Type=49)       |   FU header   | DONL (cond)   |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
 * | DONL (cond)   |                                               |
 * |-+-+-+-+-+-+-+-+                                               |
 * |                         FU payload                            |
 * |                                                               |
 * |                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                               :...OPTIONAL RTP padding        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * 4. PACI Packet
 * --------------
 *
 * TODO - Useful for embedding extensible control information like
 * Temporal Scalability Control Information (TSCI).
 */

STATUS createPayloadForH265(UINT32, PBYTE, UINT32, PBYTE, PUINT32, PUINT32, PUINT32);
STATUS createH265PayloadFromNalu(UINT32, PBYTE, UINT32, PPayloadArray, PUINT32, PUINT32);
STATUS depayH265FromRtpPayload(PBYTE pRawPacket, UINT32 packetLength, PBYTE pNaluData, PUINT32 pNaluLength, PBOOL pIsStart);

#ifdef __cplusplus
}
#endif
#endif //__KINESIS_VIDEO_WEBRTC_CLIENT_RTPH265PAYLOADER_H
