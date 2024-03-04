/*******************************************
SessionDescription internal include file
*******************************************/
#ifndef __KINESIS_VIDEO_WEBRTC_CLIENT_PEERCONNECTION_SESSIONDESCRIPTION__
#define __KINESIS_VIDEO_WEBRTC_CLIENT_PEERCONNECTION_SESSIONDESCRIPTION__

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#define SESSION_DESCRIPTION_INIT_LINE_ENDING            "\\r\\n"
#define SESSION_DESCRIPTION_INIT_LINE_ENDING_WITHOUT_CR "\\n"

#define SESSION_DESCRIPTION_INIT_TEMPLATE_HEAD "{\"type\": \"%s\", \"sdp\": \""
#define SESSION_DESCRIPTION_INIT_TEMPLATE_TAIL "\"}"

#define SDP_OFFER_VALUE  "offer"
#define SDP_ANSWER_VALUE "answer"

#define MEDIA_SECTION_AUDIO_VALUE "audio"
#define MEDIA_SECTION_VIDEO_VALUE "video"

#define SDP_TYPE_KEY  "type"
#define SDP_KEY       "sdp"
#define CANDIDATE_KEY "candidate"
#define SSRC_KEY      "ssrc"
#define BUNDLE_KEY    "BUNDLE"
#define MID_KEY       "mid"

#define H264_VALUE      "H264/90000"
#define H265_VALUE      "H265/90000"
#define OPUS_VALUE      "opus/48000"
#define VP8_VALUE       "VP8/90000"
#define MULAW_VALUE     "PCMU/8000"
#define ALAW_VALUE      "PCMA/8000"
#define RTX_VALUE       "rtx/90000"
#define RTX_CODEC_VALUE "apt="
#define FMTP_VALUE      "fmtp:"
#define RTPMAP_VALUE    "rtpmap"

#define MAX_PAYLOAD_TYPE_LENGTH (UINT64) 10
#define DEFAULT_PAYLOAD_MULAW   (UINT64) 0
#define DEFAULT_PAYLOAD_ALAW    (UINT64) 8
#define DEFAULT_PAYLOAD_OPUS    (UINT64) 111
#define DEFAULT_PAYLOAD_VP8     (UINT64) 96
#define DEFAULT_PAYLOAD_H264    (UINT64) 125
#define DEFAULT_PAYLOAD_H265    (UINT64) 104

#define DEFAULT_PAYLOAD_MULAW_STR (PCHAR) "0"
#define DEFAULT_PAYLOAD_ALAW_STR  (PCHAR) "8"

#define DEFAULT_H264_FMTP   (PCHAR) "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f"
// Being very explicit even though the default values are equivalent.
#define DEFAULT_H265_FMTP   (PCHAR) "level-id=93;profile-id=1;sprop-max-don-diff=0;tier-flag=0;tx-mode=SRST"
#define DEFAULT_OPUS_FMTP   (PCHAR) "minptime=10;useinbandfec=1"
#define H264_PROFILE_42E01F 0x42e01f
// profile-level-id:
//   A base16 [7] (hexadecimal) representation of the following
//   three bytes in the sequence parameter set NAL unit is specified
//   in [1]: 1) profile_idc, 2) a byte herein referred to as
//   profile-iop, composed of the values of constraint_set0_flag,
//   constraint_set1_flag, constraint_set2_flag,
//   constraint_set3_flag, constraint_set4_flag,
//   constraint_set5_flag, and reserved_zero_2bits in bit-
//   significance order, starting from the most-significant bit, and
//   3) level_id.
//
// Reference: https://tools.ietf.org/html/rfc6184#section-8.1
#define H264_FMTP_SUBPROFILE_MASK    0xFFFF00
#define H264_FMTP_PROFILE_LEVEL_MASK 0x0000FF

// H.265 tiers signaled by "tier-flag" in the fmtp line.
typedef enum {
    H265_TIER_MAIN = 0,
    H265_TIER_HIGH = 1,
} H265_TIER;

// H.265 profiles signaled by "profile-id" in the fmtp line.
typedef enum {
    H265_PROFILE_MAIN = 1,
    H265_PROFILE_MAIN10 = 2,
    H265_PROFILE_MAIN_STILL = 3,
    H265_PROFILE_RANGE_EXTENSIONS = 4,
    H265_PROFILE_HIGH_THROUGHPUT = 5,
    H265_PROFILE_MULTIVIEW_MAIN = 6,
    H265_PROFILE_SCALABLE_MAIN = 7,
    H265_PROFILE_3D_MAIN = 8,
    H265_PROFILE_SCREEN_CONTENT_CODING = 9,
    H265_PROFILE_SCALABLE_RANGE_EXTENSIONS = 10,
    H265_PROFILE_HIGH_THROUGHPUT_SCREEN_CONTENT_CODING = 11
} H265_PROFILE;

// H.265 levels signaled by "level-id" and "max-recv-level-id" in the fmtp line.
// Note: All values are equal to 30 times the level number.
typedef enum {
    H265_LEVEL_1 = 30,
    H265_LEVEL_2 = 60,
    H265_LEVEL_2_1 = 63,
    H265_LEVEL_3 = 90,
    H265_LEVEL_3_1 = 93,
    H265_LEVEL_4 = 120,
    H265_LEVEL_4_1 = 123,
    H265_LEVEL_5 = 150,
    H265_LEVEL_5_1 = 153,
    H265_LEVEL_5_2 = 156,
    H265_LEVEL_6 = 180,
    H265_LEVEL_6_1 = 183,
    H265_LEVEL_6_2 = 186,
} H265_LEVEL;

#define DTLS_ROLE_ACTPASS (PCHAR) "actpass"
#define DTLS_ROLE_ACTIVE  (PCHAR) "active"

#define VIDEO_CLOCKRATE (UINT64) 90000
#define OPUS_CLOCKRATE  (UINT64) 48000
#define PCM_CLOCKRATE   (UINT64) 8000

// https://tools.ietf.org/html/draft-holmer-rmcat-transport-wide-cc-extensions-01
#define TWCC_SDP_ATTR "transport-cc"
#define TWCC_EXT_URL  "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01"

STATUS setPayloadTypesFromOffer(PHashTable, PHashTable, PSessionDescription);
STATUS setPayloadTypesForOffer(PHashTable);

STATUS setTransceiverPayloadTypes(PHashTable, PHashTable, PDoubleList);
STATUS populateSessionDescription(PKvsPeerConnection, PSessionDescription, PSessionDescription);
STATUS findTransceiversByRemoteDescription(PKvsPeerConnection, PSessionDescription, PHashTable, PHashTable);
STATUS setReceiversSsrc(PSessionDescription, PDoubleList);
PCHAR fmtpForPayloadType(UINT64, PSessionDescription);
UINT64 getH264FmtpScore(PCHAR);

#ifdef __cplusplus
}
#endif
#endif /* __KINESIS_VIDEO_WEBRTC_CLIENT_PEERCONNECTION_SESSIONDESCRIPTION__ */
