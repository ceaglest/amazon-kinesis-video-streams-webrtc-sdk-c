/*******************************************
H265 RTP Payloader include file
*******************************************/
#ifndef __KINESIS_VIDEO_WEBRTC_CLIENT_RTPH265PAYLOADER_H
#define __KINESIS_VIDEO_WEBRTC_CLIENT_RTPH265PAYLOADER_H

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

typedef enum : UINT8 {
    /** Video Coding Layer NALUs 0 - 31. */
    H265_NALU_TYPE_TRAIL_N = 0,
    H265_NALU_TYPE_TRAIL_R = 1,
    H265_NALU_TYPE_TSA_N = 2,
    H265_NALU_TYPE_TSA_R = 3,
    H265_NALU_TYPE_STSA_N = 4,
    H265_NALU_TYPE_STSA_R = 5,
    H265_NALU_TYPE_RADL_N = 6,
    H265_NALU_TYPE_RADL_R = 7,
    H265_NALU_TYPE_RASL_N = 8,
    H265_NALU_TYPE_RASL_R = 9,
    H265_NALU_TYPE_RSV_VCL_N10 = 10,
    H265_NALU_TYPE_RSV_VCL_R11 = 11,
    H265_NALU_TYPE_RSV_VCL_N12 = 12,
    H265_NALU_TYPE_RSV_VCL_R13 = 13,
    H265_NALU_TYPE_RSV_VCL_N14 = 14,
    H265_NALU_TYPE_RSV_VCL_R15 = 15,
    H265_NALU_TYPE_BLA_W_LP = 16,
    H265_NALU_TYPE_BLA_W_RADL = 17,
    H265_NALU_TYPE_BLA_N_LP = 18,
    H265_NALU_TYPE_IDR_W_RADL = 19,
    H265_NALU_TYPE_IDR_N_LP = 20,
    H265_NALU_TYPE_CRA_NUT = 21,
    H265_NALU_TYPE_RSV_IRAP_VCL22 = 22,
    H265_NALU_TYPE_RSV_IRAP_VCL23 = 23,
    H265_NALU_TYPE_RSV_VCL24 = 24,
    H265_NALU_TYPE_RSV_VCL25 = 25,
    H265_NALU_TYPE_RSV_VCL26 = 26,
    H265_NALU_TYPE_RSV_VCL27 = 27,
    H265_NALU_TYPE_RSV_VCL28 = 28,
    H265_NALU_TYPE_RSV_VCL29 = 29,
    H265_NALU_TYPE_RSV_VCL30 = 30,
    H265_NALU_TYPE_RSV_VCL31 = 31,
    /** Non-Video Coding Layer NALUs 32 - 63. */
    /** The Video Parameter Set. **/
    H265_NALU_TYPE_VPS_NUT = 32,
    /** The Sequence Parameter Set. **/
    H265_NALU_TYPE_SPS_NUT = 33,
    /** The Picture Parameter Set. **/
    H265_NALU_TYPE_PPS_NUT = 34,
    /** The Access Unit Delimiter. If present, this is the first NALU in the Access Unit. **/
    H265_NALU_TYPE_AUD_NUT = 35,
    /** The end of Sequence indicator. If present, this is the last access unit in the Sequence. **/
    H265_NALU_TYPE_EOS_NUT = 36,
    /** The end of bitstream indicator. If present, this is the last access unit in the bitstream. **/
    H265_NALU_TYPE_EOB_NUT = 37,
    H265_NALU_TYPE_FD_NUT = 38,
    /** Selective Enhancement Information (S.E.I.) placed before the VCL NALUs. **/
    H265_NALU_TYPE_PREFIX_SEI_NUT = 39,
    /** S.E.I. placed after the VCL NALUs. **/
    H265_NALU_TYPE_SUFFIX_SEI_NUT = 40,
    H265_NALU_TYPE_RSV_NVCL41 = 41,
    H265_NALU_TYPE_RSV_NVCL42 = 42,
    H265_NALU_TYPE_RSV_NVCL43 = 43,
    H265_NALU_TYPE_RSV_NVCL44 = 44,
    H265_NALU_TYPE_RSV_NVCL45 = 45,
    H265_NALU_TYPE_RSV_NVCL46 = 46,
    H265_NALU_TYPE_RSV_NVCL47 = 47,
    /** An Aggregation Packet that combines multiple NALUs. **/
    H265_NALU_TYPE_AP = 48,
    /** A Fragmentation Unit Packet that fragments a single NALU across multiple RTP packets. **/
    H265_NALU_TYPE_FU = 49,
    H265_NALU_TYPE_UNSPEC50 = 50,
    H265_NALU_TYPE_UNSPEC51 = 51,
    H265_NALU_TYPE_UNSPEC52 = 52,
    H265_NALU_TYPE_UNSPEC53 = 53,
    H265_NALU_TYPE_UNSPEC54 = 54,
    H265_NALU_TYPE_UNSPEC55 = 55,
    H265_NALU_TYPE_UNSPEC56 = 56,
    H265_NALU_TYPE_UNSPEC57 = 57,
    H265_NALU_TYPE_UNSPEC58 = 58,
    H265_NALU_TYPE_UNSPEC59 = 59,
    H265_NALU_TYPE_UNSPEC60 = 60,
    H265_NALU_TYPE_UNSPEC61 = 61,
    H265_NALU_TYPE_UNSPEC62 = 62,
    H265_NALU_TYPE_UNSPEC63 = 63,
} H265_NALU_TYPE;

/**
 * @brief The masks used to parse the 2-byte H.265 NALU headers.
 * The header structure is different than the H.264 1-byte headers.
 */
typedef enum : UINT8 {
    H265_NALU_HEADER_MASK_FBIT = 0x80,
    H265_NALU_HEADER_MASK_TYPE = 0x7E,
    /* Check if the (shifted) type field is a VCL or non-VCL NALU. */
    H265_NALU_HEADER_MASK_TYPE_VCL_NALU = 0x20,
    H265_NALU_HEADER_MASK_LAYER_ID_HIGH = 0x1,
    H265_NALU_HEADER_MASK_LAYER_ID_LOW = 0xF8,
    H265_NALU_HEADER_MASK_TID = 0x07,
} H265_NALU_HEADER_MASK;

const UINT8 H265_NALU_HEADER_SIZE_BYTES;
const UINT8 H265_RTP_PAYLOAD_HEADER_SIZE_BYTES;
const UINT8 H265_RTP_FU_HEADER_SIZE_BYTES;
const UINT8 H265_RTP_FU_HEADER_FU_TYPE_SIZE_BITS;
/** The maximum number of NALUs that can be contained in a single Access Unit. The library can't send AUs larger than this. */
const UINT8 H265_ACCESS_UNIT_MAX_SIZE;

/*
 * Payload Structures
 * ------------------
 *
 * Four different payload structures are defined in rfc7798.
 * Ref: https://datatracker.ietf.org/doc/html/rfc7798#section-4.4
 *
 * 1. Single NAL unit packet
 * -------------------------
 *
 * Convey a single NALU via a single RTP packet smaller than the MTU.
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
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
 * An AP combines multiple NAL units within one access unit into a single RTP packet.
 *
 * In H.265 the Parameter Sets must be repeated with IDR AUs or signaled out of band
 * via fmtp. In many cases the non-VCL NALUs can be aggregated while still fitting
 * inside the MTU.
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |    PayloadHdr (Type=48)       |                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
 * |                                                               |
 * |             two or more aggregation units                     |
 * |                                                               |
 * |                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                               :...OPTIONAL RTP padding        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * 3. Fragmentation Units (FUs)
 * ----------------------------
 *
 * FUs convey a single NALU across MTU boundaries using multiple RTP packets.
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
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

STATUS createPayloadForH265AnnexB(UINT32, PBYTE, UINT32, PBYTE, PUINT32, PUINT32, PUINT32);
STATUS depayH265FromRtpPayload(PBYTE pRawPacket, UINT32 packetLength, PBYTE pNaluData, PUINT32 pNaluLength, PBOOL pIsStart);

#ifdef __cplusplus
}
#endif
#endif //__KINESIS_VIDEO_WEBRTC_CLIENT_RTPH265PAYLOADER_H
