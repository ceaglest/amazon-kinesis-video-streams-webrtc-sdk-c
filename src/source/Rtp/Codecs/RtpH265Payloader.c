#define LOG_CLASS "RtpH265Payloader"

#include "../../Include_i.h"

const UINT8 H265_NALU_HEADER_SIZE_BYTES = 2;
const UINT8 H265_RTP_PAYLOAD_HEADER_SIZE_BYTES = 2;
const UINT8 H265_RTP_FU_HEADER_SIZE_BYTES = 1;
const UINT8 H265_RTP_AP_NALU_SIZE_BYTES = 2;
const UINT8 H265_RTP_FU_HEADER_FU_TYPE_SIZE_BITS = 6;
// Worst case: A 16-slice IDR with VPS, SPS, PPS, SEI, AUD.
const UINT8 H265_ACCESS_UNIT_MAX_SIZE = 21;
// If aggregation packets should be used or not.
const bool H265_RTP_PAYLOADER_USE_AGGREGATION_PACKETS = false;

const BYTE H265_NALU_START_4_BYTE_CODE[] = {0x00, 0x00, 0x00, 0x01};

/* A parsed version of a Network Abstraction Layer Unit header. */
typedef struct H265NaluHeader {
    UINT8 temporalId;
    H265_NALU_TYPE type;
} H265NaluHeader;

/* A parsed version of a Network Abstraction Layer Unit. */
typedef struct H265Nalu {
    /* All of the data including the header but not the prefix. */
    PBYTE data;
    /* The length of the data including the header but not the prefix. */
    UINT32 length;
    H265NaluHeader header;
} H265Nalu;

STATUS createH265PayloadFromAu(UINT32 mtu,
                               const H265Nalu *accessUnit,
                               UINT8 accessUnitSize,
                               PPayloadArray pPayloadArray,
                               PUINT32 filledLength,
                               PUINT32 filledSubLenSize);

STATUS createH265FragmentationUnitPayloadsFromNALU(UINT32 mtu,
                                                   const H265Nalu *nalu,
                                                   PPayloadArray pPayloadArray,
                                                   PUINT32 filledLength,
                                                   PUINT32 filledSubLenSize);

STATUS createH265AggregationPacketPayloadFromNALUs(UINT32 mtu,
                                                   const H265Nalu *nalus,
                                                   UINT8 nalusSize,
                                                   PPayloadArray pPayloadArray,
                                                   PUINT32 filledLength,
                                                   PUINT32 filledSubLenSize);

STATUS createH265SingleNaluPacketPayloadFromNALU(UINT32 mtu,
                                                const H265Nalu *nalu,
                                                PPayloadArray pPayloadArray,
                                                PUINT32 filledLength,
                                                PUINT32 filledSubLenSize);

UINT8 getH265NalusThatFitInAggregationPacket(UINT32 mtu,
                                             const H265Nalu *nalus,
                                             UINT8 nalusSize);

// TODO: Conditionally compile this function when streaming logs are enabled due to binary size.
PCHAR getH265NaluTypeString(H265_NALU_TYPE type) {
    switch (type) {
        case H265_NALU_TYPE_TRAIL_N:
            return "TRAIL_N";
        case H265_NALU_TYPE_TRAIL_R:
            return "TRAIL_R";
        case H265_NALU_TYPE_TSA_N:
            return "TSA_N";
        case H265_NALU_TYPE_TSA_R:
            return "TSA_R";
        case H265_NALU_TYPE_STSA_N:
            return "STSA_N";
        case H265_NALU_TYPE_STSA_R:
            return "STSA_R";
        case H265_NALU_TYPE_RADL_N:
            return "RADL_N";
        case H265_NALU_TYPE_RADL_R:
            return "RADL_R";
        case H265_NALU_TYPE_RASL_N:
            return "RASL_N";
        case H265_NALU_TYPE_RASL_R:
            return "RASL_R";
        case H265_NALU_TYPE_RSV_VCL_N10:
            return "VCL_N10";
        case H265_NALU_TYPE_RSV_VCL_R11:
            return "VCL_R11";
        case H265_NALU_TYPE_RSV_VCL_N12:
            return "VCL_N12";
        case H265_NALU_TYPE_RSV_VCL_R13:
            return "VCL_R13";
        case H265_NALU_TYPE_RSV_VCL_N14:
            return "VCL_N14";
        case H265_NALU_TYPE_RSV_VCL_R15:
            return "VCL_R15";
        case H265_NALU_TYPE_BLA_W_LP:
            return "BLA_W_LP";
        case H265_NALU_TYPE_BLA_W_RADL:
            return "BLA_W_RADL";
        case H265_NALU_TYPE_BLA_N_LP:
            return "BLA_N_LP";
        case H265_NALU_TYPE_IDR_W_RADL:
            return "IDR_W_RADL";
        case H265_NALU_TYPE_IDR_N_LP:
            return "IDR_N_LP";
        case H265_NALU_TYPE_CRA_NUT:
            return "CRA_NUT";
        case H265_NALU_TYPE_RSV_IRAP_VCL22:
            return "RSV_IRAP_VCL22";
        case H265_NALU_TYPE_RSV_IRAP_VCL23:
            return "RSV_IRAP_VCL23";
        case H265_NALU_TYPE_RSV_VCL24:
            return "RSV_VCL24";
        case H265_NALU_TYPE_RSV_VCL25:
            return "RSV_VCL25";
        case H265_NALU_TYPE_RSV_VCL26:
            return "RSV_VCL26";
        case H265_NALU_TYPE_RSV_VCL27:
            return "RSV_VCL27";
        case H265_NALU_TYPE_RSV_VCL28:
            return "RSV_VCL28";
        case H265_NALU_TYPE_RSV_VCL29:
            return "RSV_VCL29";
        case H265_NALU_TYPE_RSV_VCL30:
            return "RSV_VCL30";
        case H265_NALU_TYPE_RSV_VCL31:
            return "VCL31";
        case H265_NALU_TYPE_VPS_NUT:
            return "VPS_NUT";
        case H265_NALU_TYPE_SPS_NUT:
            return "SPS_NUT";
        case H265_NALU_TYPE_PPS_NUT:
            return "PPS_NUT";
        case H265_NALU_TYPE_AUD_NUT:
            return "AUD_NUT";
        case H265_NALU_TYPE_EOS_NUT:
            return "EOS_NUT";
        case H265_NALU_TYPE_EOB_NUT:
            return "EOB_NUT";
        case H265_NALU_TYPE_FD_NUT:
            return "FD_NUT";
        case H265_NALU_TYPE_PREFIX_SEI_NUT:
            return "PREFIX_SEI_NUT";
        case H265_NALU_TYPE_SUFFIX_SEI_NUT:
            return "SUFFIX_SEI_NUT";
        case H265_NALU_TYPE_RSV_NVCL41:
            return "RSV_NVCL41";
        case H265_NALU_TYPE_RSV_NVCL42:
            return "RSV_NVCL42";
        case H265_NALU_TYPE_RSV_NVCL43:
            return "RSV_NVCL43";
        case H265_NALU_TYPE_RSV_NVCL44:
            return "RSV_NVCL44";
        case H265_NALU_TYPE_RSV_NVCL45:
            return "RSV_NVCL45";
        case H265_NALU_TYPE_RSV_NVCL46:
            return "RSV_NVCL46";
        case H265_NALU_TYPE_RSV_NVCL47:
            return "RSV_NVCL47";
        case H265_NALU_TYPE_AP:
            return "AP";
        case H265_NALU_TYPE_FU:
            return "FU";
        case H265_NALU_TYPE_PACI:
            return "PACI";
        case H265_NALU_TYPE_UNSPEC51:
            return "UNSPEC51";
        case H265_NALU_TYPE_UNSPEC52:
            return "UNSPEC52";
        case H265_NALU_TYPE_UNSPEC53:
            return "UNSPEC53";
        case H265_NALU_TYPE_UNSPEC54:
            return "UNSPEC54";
        case H265_NALU_TYPE_UNSPEC55:
            return "UNSPEC55";
        case H265_NALU_TYPE_UNSPEC56:
            return "UNSPEC56";
        case H265_NALU_TYPE_UNSPEC57:
            return "UNSPEC57";
        case H265_NALU_TYPE_UNSPEC58:
            return "UNSPEC58";
        case H265_NALU_TYPE_UNSPEC59:
            return "UNSPEC59";
        case H265_NALU_TYPE_UNSPEC60:
            return "UNSPEC60";
        case H265_NALU_TYPE_UNSPEC61:
            return "UNSPEC61";
        case H265_NALU_TYPE_UNSPEC62:
            return "UNSPEC62";
        case H265_NALU_TYPE_UNSPEC63:
            return "UNSPEC63";
        default:
            return "UNKNOWN";
    }
}

UINT8 getH265NalusThatFitInAggregationPacket(UINT32 mtu,
                                             const H265Nalu *nalus,
                                             UINT8 nalusSize)
{
    UINT8 nalusThatFitInAp = 0;
    UINT32 bytesRemainingInAp = mtu - H265_RTP_PAYLOAD_HEADER_SIZE_BYTES;
    for (UINT8 naluIndex = 0; naluIndex < nalusSize; naluIndex++) {
        bytesRemainingInAp -= H265_RTP_AP_NALU_SIZE_BYTES;

        const H265Nalu nalu = nalus[naluIndex];
        if (nalu.length > bytesRemainingInAp) {
            break;
        }
        nalusThatFitInAp++;
        bytesRemainingInAp -= nalu.length;
    }
    return nalusThatFitInAp;
}

STATUS createPayloadForH265AnnexB(UINT32 mtu,
                                  PBYTE accessUnit,
                                  UINT32 acessUnitLength,
                                  PBYTE payloadBuffer,
                                  PUINT32 pPayloadLength,
                                  PUINT32 pPayloadSubLength,
                                  PUINT32 pPayloadSubLenSize)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;

    PBYTE curPtrInNalus = accessUnit;
    UINT32 remainNalusLength = acessUnitLength;
    UINT32 nextNaluLength = 0;
    UINT32 startIndex = 0;
    UINT32 auPayloadsLength = 0;
    UINT32 auPayloadsSubLenSize = 0;
    BOOL sizeCalculationOnly = (payloadBuffer == NULL);
    PayloadArray payloadArray;
    UINT8 currentNaluIndex = 0;
    H265Nalu parsedAccessUnits[H265_ACCESS_UNIT_MAX_SIZE];

    CHK(accessUnit != NULL && pPayloadSubLenSize != NULL && pPayloadLength != NULL && (sizeCalculationOnly || pPayloadSubLength != NULL), STATUS_NULL_ARG);

    payloadArray.payloadLength = 0;
    payloadArray.payloadSubLenSize = 0;
    if (sizeCalculationOnly) {
        payloadArray.maxPayloadLength = 0;
        payloadArray.maxPayloadSubLenSize = 0;
    } else {
        payloadArray.maxPayloadLength = *pPayloadLength;
        payloadArray.maxPayloadSubLenSize = *pPayloadSubLenSize;
    }
    payloadArray.payloadBuffer = payloadBuffer;
    payloadArray.payloadSubLength = pPayloadSubLength;

    // The NALUs are in Annex-B format. Skip the start codes ('{00 00 01}' or '{00 00 00 01}') which are not packetized.
    do {
        CHK_STATUS(getNextNaluLength(curPtrInNalus, remainNalusLength, &startIndex, &nextNaluLength));
        CHK_ERR(currentNaluIndex < H265_ACCESS_UNIT_MAX_SIZE, STATUS_RTP_H265_ACCESS_UNIT_TOO_LARGE,
                "The access unit contains too many NALUs to send.");

        /*
         * Parse the NALU header.
         *
         * +---------------+---------------+
         * |0|1|2|3|4|5|6|7|0|1|2|3|4|5|6|7|
         * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         * |F|   Type    |  LayerId  | TID |
         * +-------------+-----------------+
         */
        PBYTE naluHeader = curPtrInNalus + startIndex;
        UINT8 fBit = (naluHeader[0] & H265_NALU_HEADER_MASK_FBIT) >> 7;
        BYTE nuhTemporalIdPlusOne = (naluHeader[1] & H265_NALU_HEADER_MASK_TID);
        CHK_ERR(nuhTemporalIdPlusOne > 0, STATUS_RTP_INVALID_NALU, "The nuh_temporal_id_plus1 must be greater than zero.");
        CHK_ERR(fBit == 0, STATUS_RTP_INVALID_NALU, "The forbidden bit must be set to zero.");

        parsedAccessUnits[currentNaluIndex] = (H265Nalu){
            curPtrInNalus + startIndex,
            nextNaluLength,
            (H265NaluHeader){
                nuhTemporalIdPlusOne - 1,
                (naluHeader[0] & H265_NALU_HEADER_MASK_TYPE) >> 1
            }
        };
        curPtrInNalus += startIndex + nextNaluLength;
        remainNalusLength -= startIndex + nextNaluLength;
        currentNaluIndex++;
    } while (remainNalusLength != 0);
    
    // Packetize the parsed NALUs.
    if (sizeCalculationOnly) {
        CHK_STATUS(createH265PayloadFromAu(mtu, parsedAccessUnits, currentNaluIndex, NULL, &auPayloadsLength, &auPayloadsSubLenSize));
        payloadArray.payloadLength += auPayloadsLength;
        payloadArray.payloadSubLenSize += auPayloadsSubLenSize;
    } else {
        CHK_STATUS(createH265PayloadFromAu(mtu, parsedAccessUnits, currentNaluIndex, &payloadArray, &auPayloadsLength, &auPayloadsSubLenSize));
    }

CleanUp:
    if (pPayloadSubLenSize != NULL && pPayloadLength != NULL) {
        *pPayloadLength = payloadArray.payloadLength;
        *pPayloadSubLenSize = payloadArray.payloadSubLenSize;
    }

    LEAVES();
    return retStatus;
}

STATUS createH265PayloadFromAu(UINT32 mtu,
                               const H265Nalu *accessUnit,
                               UINT8 accessUnitSize,
                               PPayloadArray pPayloadArray,
                               PUINT32 filledLength,
                               PUINT32 filledSubLenSize)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    BOOL sizeCalculationOnly = (pPayloadArray == NULL);

    CHK(accessUnit != NULL && accessUnitSize > 0 && filledLength != NULL && filledSubLenSize != NULL, STATUS_NULL_ARG);
    CHK(sizeCalculationOnly || (pPayloadArray->payloadSubLength != NULL && pPayloadArray->payloadBuffer != NULL), STATUS_NULL_ARG);
    CHK(mtu > H265_RTP_PAYLOAD_HEADER_SIZE_BYTES + H265_RTP_FU_HEADER_SIZE_BYTES, STATUS_RTP_INPUT_MTU_TOO_SMALL);
    
    for (UINT8 naluIndex = 0; naluIndex < accessUnitSize; naluIndex++) {
        UINT32 singlePayloadLength = 0;
        UINT32 singlePayloadSubLenSize = 0;
        const H265Nalu *nalu = &accessUnit[naluIndex];
        H265_NALU_TYPE naluType = nalu->header.type;
        
        if (naluType == H265_NALU_TYPE_AUD_NUT || naluType == H265_NALU_TYPE_EOS_NUT) {
            // With SRST the RTP marker bit indicating the end of a frame is equivalent to the AUD starting a new one.
            // Similarly, a new keyframe can be used to infer the end of the previous coded video sequence.
        } else if (nalu->length <= mtu) {
            UINT8 nalusThatFitInAp = getH265NalusThatFitInAggregationPacket(mtu, nalu, accessUnitSize - naluIndex);
            if (H265_RTP_PAYLOADER_USE_AGGREGATION_PACKETS && nalusThatFitInAp > 1) {
                CHK_STATUS(createH265AggregationPacketPayloadFromNALUs(mtu, nalu, nalusThatFitInAp,
                                                                       pPayloadArray, &singlePayloadLength,
                                                                       &singlePayloadSubLenSize));
                // Skip the already aggregated NALUs.
                naluIndex += nalusThatFitInAp - 1;
            } else {
                CHK_STATUS(createH265SingleNaluPacketPayloadFromNALU(mtu, nalu, pPayloadArray,
                                                                     &singlePayloadLength, &singlePayloadSubLenSize));
            }
        } else {
            CHK_STATUS(createH265FragmentationUnitPayloadsFromNALU(mtu, nalu, pPayloadArray,
                                                                   &singlePayloadLength, &singlePayloadSubLenSize));
        }
        *filledLength += singlePayloadLength;
        *filledSubLenSize += singlePayloadSubLenSize;
        
        if (!sizeCalculationOnly) {
            pPayloadArray->payloadBuffer += singlePayloadLength;
            pPayloadArray->payloadLength += singlePayloadLength;
            pPayloadArray->maxPayloadLength -= singlePayloadLength;
            pPayloadArray->payloadSubLenSize += singlePayloadSubLenSize;
            pPayloadArray->maxPayloadSubLenSize -= singlePayloadSubLenSize;
        }
    }

CleanUp:
    if (STATUS_FAILED(retStatus) && sizeCalculationOnly) {
        pPayloadArray->payloadLength = 0;
        pPayloadArray->payloadSubLenSize = 0;
    }

    LEAVES();
    return retStatus;
}

STATUS createH265FragmentationUnitPayloadsFromNALU(UINT32 mtu,
                                                   const H265Nalu *nalu,
                                                   PPayloadArray pPayloadArray,
                                                   PUINT32 filledLength,
                                                   PUINT32 filledSubLenSize)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    
    // FU: https://tools.ietf.org/html/rfc7798#section-4.4.3
    PBYTE pPayload = NULL;
    UINT32 remainingNaluLength = nalu->length;
    UINT32 maxPayloadSize = mtu - H265_RTP_PAYLOAD_HEADER_SIZE_BYTES - H265_RTP_FU_HEADER_SIZE_BYTES;
    UINT8 payloadHdr[H265_RTP_PAYLOAD_HEADER_SIZE_BYTES];
    BOOL sizeCalculationOnly = (pPayloadArray == NULL);
    PBYTE pCurPtrInNalu = nalu->data;
    UINT32 curPayloadSize = 0;
    UINT32 payloadLength = 0;
    UINT32 payloadSubLenSizeIndex = pPayloadArray ? pPayloadArray->payloadSubLenSize : 0;
    UINT32 payloadSubLenSize = 0;
    
    if (!sizeCalculationOnly) {
        pPayload = pPayloadArray->payloadBuffer;
        
        // TODO: Migrate to DLOGS, this is very noisy.
        DLOGI("[RtpH265Payloader] Create Fragmented Unit payload. Type: %s, TID: %" PRIu8 ", length: %d",
              getH265NaluTypeString(nalu->header.type),
              nalu->header.temporalId,
              nalu->length);

        /*
         * Construct the PayloadHdr common to each packet.
         *
         * F, LayerId, and TID MUST be equal to the original NAL.
         *
         * +---------------+---------------+
         * |0|1|2|3|4|5|6|7|0|1|2|3|4|5|6|7|
         * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         * |F| Type (49) |  LayerId  | TID |
         * +-------------+-----------------+
         */
        memcpy(&payloadHdr, pCurPtrInNalu, H265_NALU_HEADER_SIZE_BYTES);
        UINT8 layerIdHigh = (payloadHdr[0] & H265_NALU_HEADER_MASK_LAYER_ID_HIGH);
        UINT8 fuTypeShifted = (H265_NALU_TYPE_FU << 1);
        UINT8 fBitShifted = (payloadHdr[0] & H265_NALU_HEADER_MASK_FBIT);
        payloadHdr[0] = fBitShifted | fuTypeShifted | layerIdHigh;
    }
    
    // The PayloadHdr + FU header contain equivalent information to the NALU header. It is removed.
    remainingNaluLength -= H265_NALU_HEADER_SIZE_BYTES;
    pCurPtrInNalu += H265_NALU_HEADER_SIZE_BYTES;
    
    while (remainingNaluLength != 0) {
        // TODO: Consider fragmenting into equal payload sizes for packet loss and delay reasons.
        curPayloadSize = MIN(maxPayloadSize, remainingNaluLength);
        payloadLength += H265_RTP_PAYLOAD_HEADER_SIZE_BYTES + H265_RTP_FU_HEADER_SIZE_BYTES + curPayloadSize;
        payloadSubLenSize += 1;

        if (!sizeCalculationOnly) {
            CHK(payloadSubLenSize <= pPayloadArray->maxPayloadSubLenSize && payloadLength <= pPayloadArray->maxPayloadLength,
                STATUS_BUFFER_TOO_SMALL);
            
            /*
             * Write the common PayloadHdr.
             * Note: The DONL field is skipped when sprop-max-don-diff == 0.
             */
            MEMCPY(pPayload, payloadHdr, H265_RTP_PAYLOAD_HEADER_SIZE_BYTES);
            
            /*
             * Write the FU header.
             * +---------------+
             * |0|1|2|3|4|5|6|7|
             * +-+-+-+-+-+-+-+-+
             * |S|E|  FuType   |
             * +---------------+
             */
            pPayload[H265_RTP_PAYLOAD_HEADER_SIZE_BYTES] = nalu->header.type;
            if (remainingNaluLength == nalu->length - H265_NALU_HEADER_SIZE_BYTES) {
                // Set for starting bit
                pPayload[H265_RTP_PAYLOAD_HEADER_SIZE_BYTES] |= 0x1 << (H265_RTP_FU_HEADER_FU_TYPE_SIZE_BITS + 1);
            } else if (remainingNaluLength == curPayloadSize) {
                // Set for ending bit
                pPayload[H265_RTP_PAYLOAD_HEADER_SIZE_BYTES] |= 0x1 << H265_RTP_FU_HEADER_FU_TYPE_SIZE_BITS;
            }
            
            // Write the payload.
            MEMCPY(pPayload + H265_RTP_PAYLOAD_HEADER_SIZE_BYTES + H265_RTP_FU_HEADER_SIZE_BYTES, pCurPtrInNalu, curPayloadSize);
            
            pPayloadArray->payloadSubLength[payloadSubLenSizeIndex] = H265_RTP_PAYLOAD_HEADER_SIZE_BYTES + H265_RTP_FU_HEADER_SIZE_BYTES + curPayloadSize;
            pPayload += pPayloadArray->payloadSubLength[payloadSubLenSizeIndex];
        }
        
        payloadSubLenSizeIndex += 1;
        pCurPtrInNalu += curPayloadSize;
        remainingNaluLength -= curPayloadSize;
    }
CleanUp:
    if (STATUS_FAILED(retStatus) && sizeCalculationOnly) {
        payloadLength = 0;
        payloadSubLenSize = 0;
    }

    if (filledLength != NULL && filledSubLenSize != NULL) {
        *filledLength = payloadLength;
        *filledSubLenSize = payloadSubLenSize;
    }

    LEAVES();
    return retStatus;
}

STATUS createH265SingleNaluPacketPayloadFromNALU(UINT32 mtu,
                                                 const H265Nalu *nalu,
                                                 PPayloadArray pPayloadArray,
                                                 PUINT32 filledLength,
                                                 PUINT32 filledSubLenSize)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;

    // Single NALU: https://tools.ietf.org/html/rfc7798#section-4.4.1
    UINT32 payloadLength = nalu->length;
    UINT32 payloadSubLenSize = 1;
    BOOL sizeCalculationOnly = (pPayloadArray == NULL);
    
    if (!sizeCalculationOnly) {
        UINT32 payloadSubLenSizeIndex = pPayloadArray->payloadSubLenSize;
        
        CHK(*filledSubLenSize <= pPayloadArray->maxPayloadSubLenSize && *filledLength <= pPayloadArray->maxPayloadLength,
            STATUS_BUFFER_TOO_SMALL);

        // TODO: Migrate to DLOGS, this is very noisy.
        DLOGI("[RtpH265Payloader] Create Single NALU payload. Type: %s, TID: %" PRIu8 ", length: %d",
              getH265NaluTypeString(nalu->header.type),
              nalu->header.temporalId,
              nalu->length);

        // The DONL field is not present because the library does not negotiate frame reordering.
        MEMCPY(pPayloadArray->payloadBuffer, nalu->data, payloadLength);
        pPayloadArray->payloadSubLength[payloadSubLenSizeIndex] = payloadLength;
    }

CleanUp:
    if (STATUS_FAILED(retStatus) && sizeCalculationOnly) {
        payloadLength = 0;
        payloadSubLenSize = 0;
    }

    if (filledLength != NULL && filledSubLenSize != NULL) {
        *filledLength = payloadLength;
        *filledSubLenSize = payloadSubLenSize;
    }

    LEAVES();
    return retStatus;
}

STATUS createH265AggregationPacketPayloadFromNALUs(UINT32 mtu,
                                                   const H265Nalu *nalus,
                                                   UINT8 nalusSize,
                                                   PPayloadArray pPayloadArray,
                                                   PUINT32 filledLength,
                                                   PUINT32 filledSubLenSize)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;

    // Aggregation Packets (APs): https://tools.ietf.org/html/rfc7798#section-4.4.2
    PBYTE pPayload = NULL;
    UINT8 payloadHdr[H265_RTP_PAYLOAD_HEADER_SIZE_BYTES];
    UINT32 payloadLength = 0;
    UINT32 payloadSubLenSize = 1;
    BOOL sizeCalculationOnly = (pPayloadArray == NULL);
    
    UINT8 lowestTid = UINT8_MAX;
    // TODO: Parse and check the Fbit. It's normally set to 0.
    UINT8 forbiddenBit = 0;
    // TODO: Parse and check the layerId. It's normally set to 0 but can be set to higher values in extensions to HEVC.
    UINT8 lowestLayerId = 0;
    payloadLength += H265_RTP_PAYLOAD_HEADER_SIZE_BYTES;
    for (UINT8 i = 0; i < nalusSize; i++) {
        payloadLength += nalus[i].length + H265_RTP_AP_NALU_SIZE_BYTES;
        if (nalus[i].header.temporalId < lowestTid) {
            lowestTid = nalus[i].header.temporalId;
        }
    }

    if (!sizeCalculationOnly) {
        UINT32 payloadSubLenSizeIndex = pPayloadArray->payloadSubLenSize;
        pPayload = pPayloadArray->payloadBuffer;

        CHK(*filledSubLenSize <= pPayloadArray->maxPayloadSubLenSize && *filledLength <= pPayloadArray->maxPayloadLength,
            STATUS_BUFFER_TOO_SMALL);

        // TODO: Migrate to DLOGS, this is very noisy.
        DLOGI("[RtpH265Payloader] Create Aggregation Packet payload. First type: %s, TID: %" PRIu8 ", payload length: %d",
              getH265NaluTypeString(nalus[0].header.type),
              lowestTid,
              payloadLength);
        
        /*
         * Construct the PayloadHdr for the RTP payload.
         *
         * The F bit MUST
         * be equal to 0 if the F bit of each aggregated NAL unit is equal to
         * zero; otherwise, it MUST be equal to 1. The Type field MUST be equal
         * to 48.  The value of LayerId MUST be equal to the lowest value of
         * LayerId of all the aggregated NAL units.  The value of TID MUST be
         * the lowest value of TID of all the aggregated NAL units.
         *
         * +---------------+---------------+
         * |0|1|2|3|4|5|6|7|0|1|2|3|4|5|6|7|
         * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         * |F| Type (48) |  LayerId  | TID |
         * +-------------+-----------------+
         */
        UINT8 apTypeShifted = (H265_NALU_TYPE_AP << 1);
        UINT8 layerIdHigh = (lowestLayerId >> 7) & H265_NALU_HEADER_MASK_LAYER_ID_HIGH;
        UINT8 fBitShifted = (forbiddenBit & H265_NALU_HEADER_MASK_FBIT);
        UINT8 layerIdLowShifted = (lowestLayerId & H265_NALU_HEADER_MASK_LAYER_ID_LOW);
        payloadHdr[0] = fBitShifted | apTypeShifted | layerIdHigh;
        payloadHdr[1] = layerIdLowShifted | lowestTid;
        
        /*
         * Write the common PayloadHdr.
         * Note: The DONL field is skipped when sprop-max-don-diff == 0.
         */
        MEMCPY(pPayload, payloadHdr, H265_RTP_PAYLOAD_HEADER_SIZE_BYTES);
        pPayloadArray->payloadSubLength[payloadSubLenSizeIndex] = H265_RTP_PAYLOAD_HEADER_SIZE_BYTES;
        pPayload += H265_RTP_PAYLOAD_HEADER_SIZE_BYTES;
        
        for (UINT8 i = 0; i < nalusSize; i++) {
            // Copy the NALU size header.
            UINT32 naluSize = nalus[i].length;
            CHK_ERR(naluSize <= UINT16_MAX, STATUS_RTP_INVALID_NALU, "The NALU is too large to aggregate.");
            putUnalignedInt16BigEndian((PINT16) pPayload, (UINT16)naluSize);
            
            // Copy the NALU payload (header + body)
            // Note: The DONL field is not present because the library does not negotiate frame reordering.
            MEMCPY(pPayload + H265_RTP_AP_NALU_SIZE_BYTES, nalus[i].data, naluSize);
            pPayloadArray->payloadSubLength[payloadSubLenSizeIndex] += H265_RTP_AP_NALU_SIZE_BYTES + naluSize;
            pPayload += H265_RTP_AP_NALU_SIZE_BYTES + naluSize;
        }
    }

CleanUp:
    if (STATUS_FAILED(retStatus) && sizeCalculationOnly) {
        payloadLength = 0;
        payloadSubLenSize = 0;
    }

    if (filledLength != NULL && filledSubLenSize != NULL) {
        *filledLength = payloadLength;
        *filledSubLenSize = payloadSubLenSize;
    }

    LEAVES();
    return retStatus;
}

STATUS depayH265AnnexBFromRtpPayload(PBYTE pRawPacket, UINT32 packetLength, PBYTE pNaluData, PUINT32 pNaluLength, PBOOL pIsStart) {
    STATUS retStatus = STATUS_SUCCESS;
    
    BOOL sizeCalculationOnly = (pNaluData == NULL);
    BOOL isStartingPacket = FALSE;
    PBYTE pCurPtr = pRawPacket;
    UINT32 naluLength = 0;
    H265_NALU_TYPE naluType = (*pRawPacket & H265_NALU_HEADER_MASK_TYPE) >> 1;
    
    CHK(pRawPacket != NULL && pNaluLength != NULL, STATUS_NULL_ARG);
    CHK(packetLength > 0, retStatus);
    
    if (naluType == H265_NALU_TYPE_AP) {
        // TODO: Implement de-payloading of APs.
        CHK(FALSE, STATUS_NOT_IMPLEMENTED);
    } else if (naluType == H265_NALU_TYPE_FU) {
        // TODO: Implement de-payloading of FUs.
        CHK(FALSE, STATUS_NOT_IMPLEMENTED);
    } else if (naluType == H265_NALU_TYPE_PACI) {
        // TODO: Implement de-payloading of PACI packets.
        CHK(FALSE, STATUS_NOT_IMPLEMENTED);
    } else if (naluType >= H265_NALU_TYPE_UNSPEC51) {
        // Drop the unspecified packet.
        naluLength = 0;
        isStartingPacket = true;
    } else {
        naluLength = packetLength + sizeof(H265_NALU_START_4_BYTE_CODE);
        isStartingPacket = true;
    }
    
    // Return early with the size if given buffer is NULL
    CHK(!sizeCalculationOnly, retStatus);
    CHK(naluLength <= *pNaluLength, STATUS_BUFFER_TOO_SMALL);
    
    if (isStartingPacket) {
        MEMCPY(pNaluData, H265_NALU_START_4_BYTE_CODE, SIZEOF(H265_NALU_START_4_BYTE_CODE));
        naluLength -= SIZEOF(H265_NALU_START_4_BYTE_CODE);
        pNaluData += SIZEOF(H265_NALU_START_4_BYTE_CODE);
    }
    DLOGI("Single NALU type %s start %d len %d", getH265NaluTypeString(naluType), isStartingPacket, packetLength);
    MEMCPY(pNaluData, pRawPacket, naluLength);
    if (isStartingPacket) {
        naluLength += SIZEOF(H265_NALU_START_4_BYTE_CODE);
    }
    DLOGS("Wrote naluLength %d isStartingPacket %d", naluLength, isStartingPacket);

CleanUp:
    if (STATUS_FAILED(retStatus) && sizeCalculationOnly) {
        naluLength = 0;
    }

    if (pNaluLength != NULL) {
        *pNaluLength = naluLength;
    }

    if (pIsStart != NULL) {
        *pIsStart = isStartingPacket;
    }

    LEAVES();
    return retStatus;
}
