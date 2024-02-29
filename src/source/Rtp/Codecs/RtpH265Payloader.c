#define LOG_CLASS "RtpH265Payloader"

#include "../../Include_i.h"

const UINT8 H265_NALU_HEADER_SIZE_BYTES = 2;
const UINT8 H265_RTP_PAYLOAD_HEADER_SIZE_BYTES = 2;
const UINT8 H265_RTP_FU_HEADER_SIZE_BYTES = 1;
const UINT8 H265_RTP_FU_HEADER_FU_TYPE_SIZE_BITS = 6;

STATUS createPayloadForH265(UINT32 mtu,
                            PBYTE nalus,
                            UINT32 nalusLength,
                            PBYTE payloadBuffer,
                            PUINT32 pPayloadLength,
                            PUINT32 pPayloadSubLength,
                            PUINT32 pPayloadSubLenSize)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PBYTE curPtrInNalus = nalus;
    UINT32 remainNalusLength = nalusLength;
    UINT32 nextNaluLength = 0;
    UINT32 startIndex = 0;
    UINT32 singlePayloadLength = 0;
    UINT32 singlePayloadSubLenSize = 0;
    BOOL sizeCalculationOnly = (payloadBuffer == NULL);
    PayloadArray payloadArray;

    CHK(nalus != NULL && pPayloadSubLenSize != NULL && pPayloadLength != NULL && (sizeCalculationOnly || pPayloadSubLength != NULL), STATUS_NULL_ARG);
    CHK(mtu > FU_A_HEADER_SIZE, STATUS_RTP_INPUT_MTU_TOO_SMALL);

    if (sizeCalculationOnly) {
        payloadArray.payloadLength = 0;
        payloadArray.payloadSubLenSize = 0;
        payloadArray.maxPayloadLength = 0;
        payloadArray.maxPayloadSubLenSize = 0;
    } else {
        payloadArray.payloadLength = *pPayloadLength;
        payloadArray.payloadSubLenSize = *pPayloadSubLenSize;
        payloadArray.maxPayloadLength = *pPayloadLength;
        payloadArray.maxPayloadSubLenSize = *pPayloadSubLenSize;
    }
    payloadArray.payloadBuffer = payloadBuffer;
    payloadArray.payloadSubLength = pPayloadSubLength;

    do {
        CHK_STATUS(getNextNaluLength(curPtrInNalus, remainNalusLength, &startIndex, &nextNaluLength));

        curPtrInNalus += startIndex;

        remainNalusLength -= startIndex;

        CHK(remainNalusLength != 0, retStatus);

        if (sizeCalculationOnly) {
            CHK_STATUS(createH265PayloadFromNalu(mtu, curPtrInNalus, nextNaluLength, NULL, &singlePayloadLength, &singlePayloadSubLenSize));
            payloadArray.payloadLength += singlePayloadLength;
            payloadArray.payloadSubLenSize += singlePayloadSubLenSize;
        } else {
            CHK_STATUS(createH265PayloadFromNalu(mtu, curPtrInNalus, nextNaluLength, &payloadArray, &singlePayloadLength, &singlePayloadSubLenSize));
            payloadArray.payloadBuffer += singlePayloadLength;
            payloadArray.payloadSubLength += singlePayloadSubLenSize;
            payloadArray.maxPayloadLength -= singlePayloadLength;
            payloadArray.maxPayloadSubLenSize -= singlePayloadSubLenSize;
        }

        remainNalusLength -= nextNaluLength;
        curPtrInNalus += nextNaluLength;
    } while (remainNalusLength != 0);

CleanUp:
    if (STATUS_FAILED(retStatus) && sizeCalculationOnly) {
        payloadArray.payloadLength = 0;
        payloadArray.payloadSubLenSize = 0;
    }

    if (pPayloadSubLenSize != NULL && pPayloadLength != NULL) {
        *pPayloadLength = payloadArray.payloadLength;
        *pPayloadSubLenSize = payloadArray.payloadSubLenSize;
    }

    LEAVES();
    return retStatus;
}

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
        case H265_NALU_TYPE_UNSPEC50:
            return "UNSPEC50";
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
    }
}

STATUS createH265PayloadFromNalu(UINT32 mtu,
                                 PBYTE nalu,
                                 UINT32 naluLength,
                                 PPayloadArray pPayloadArray,
                                 PUINT32 filledLength,
                                 PUINT32 filledSubLenSize)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PBYTE pPayload = NULL;
    UINT8 fBit = 0;
    UINT8 naluType = 0;
    UINT8 nuhLayerId = 0;
    BYTE nuhTemporalIdPlusOne = 0;
    UINT8 nuhTemporalId = 0;
    UINT32 maxPayloadSize = 0;
    UINT32 curPayloadSize = 0;
    UINT32 remainingNaluLength = naluLength;
    UINT32 payloadLength = 0;
    UINT32 payloadSubLenSize = 0;
    PBYTE pCurPtrInNalu = NULL;
    BOOL sizeCalculationOnly = (pPayloadArray == NULL);

    CHK(nalu != NULL && filledLength != NULL && filledSubLenSize != NULL, STATUS_NULL_ARG);
    sizeCalculationOnly = (pPayloadArray == NULL);
    CHK(sizeCalculationOnly || (pPayloadArray->payloadSubLength != NULL && pPayloadArray->payloadBuffer != NULL), STATUS_NULL_ARG);
    CHK(mtu > H265_RTP_PAYLOAD_HEADER_SIZE_BYTES, STATUS_RTP_INPUT_MTU_TOO_SMALL);

    /*
     * Parse the NALU header.
     *
     * +---------------+---------------+
     * |0|1|2|3|4|5|6|7|0|1|2|3|4|5|6|7|
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |F|   Type    |  LayerId  | TID |
     * +-------------+-----------------+
     */
    naluType = (nalu[0] & H265_NALU_HEADER_MASK_TYPE) >> 1;
    fBit = (nalu[0] & H265_NALU_HEADER_MASK_FBIT) >> 7;
    nuhTemporalIdPlusOne = (nalu[1] & H265_NALU_HEADER_MASK_TID);
    CHK_ERR(nuhTemporalIdPlusOne > 0, STATUS_RTP_INVALID_NALU, "The nuh_temporal_id_plus1 must be greater than zero.");
    CHK_ERR(fBit == 0, STATUS_RTP_INVALID_NALU, "The forbidden bit must be set to zero.");
    nuhTemporalId = nuhTemporalIdPlusOne - 1;
    
    if (!sizeCalculationOnly) {
        // TODO: Migrate to DLOGS, this is very noisy.
        DLOGI("[RtpH265Payloader] Create payload for NALU. Type: %s, TID: %" PRIu8 ", length: %d",
              getH265NaluTypeString(naluType),
              nuhTemporalId,
              naluLength);
        pPayload = pPayloadArray->payloadBuffer;
    }

    // TODO: Consider using Aggregation Packets for non-VCL NALUs. From 4.6:
    // For example, non-VCL NAL units such as access unit
    // delimiters, parameter sets, or SEI NAL units are typically small
    // and can often be aggregated with VCL NAL units without violating
    // MTU size constraints.
    if (naluType == H265_NALU_TYPE_AUD_NUT || naluType == H265_NALU_TYPE_EOS_NUT) {
        // With SRST there is no need to send an Access Unit Delimiter as the RTP marker bit is equivalent.
        payloadLength += 0;
        payloadSubLenSize += 0;
    } else if (naluLength <= mtu) {
        // Single NALU: https://tools.ietf.org/html/rfc7798#section-4.4.1
        payloadLength += naluLength;
        payloadSubLenSize++;

        if (!sizeCalculationOnly) {
            CHK(payloadSubLenSize <= pPayloadArray->maxPayloadSubLenSize && payloadLength <= pPayloadArray->maxPayloadLength,
                STATUS_BUFFER_TOO_SMALL);

            // The DONL field is not present because the library does not negotiate frame reordering.
            MEMCPY(pPayload, nalu, naluLength);
            pPayloadArray->payloadSubLength[payloadSubLenSize - 1] = naluLength;
            pPayload += naluLength;
        }
    } else {
        // FU: https://tools.ietf.org/html/rfc7798#section-4.4.3
        maxPayloadSize = mtu - H265_RTP_PAYLOAD_HEADER_SIZE_BYTES - H265_RTP_FU_HEADER_SIZE_BYTES;
        
        UINT8 payloadHdr[H265_RTP_PAYLOAD_HEADER_SIZE_BYTES];
        if (!sizeCalculationOnly) {
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
            memcpy(&payloadHdr, nalu, H265_NALU_HEADER_SIZE_BYTES);
            UINT8 fuTypeShifted = (H265_NALU_TYPE_FU << 1);
            UINT8 layerIdHigh = (payloadHdr[0] * H265_NALU_HEADER_MASK_LAYER_ID_HIGH);
            UINT8 fBitShifted = (payloadHdr[0] & H265_NALU_HEADER_MASK_FBIT);
            payloadHdr[0] = fBitShifted | fuTypeShifted | layerIdHigh;
        }
        
        // The PayloadHdr + FU header contain equivalent information to the NALU header. It is removed.
        remainingNaluLength -= H265_NALU_HEADER_SIZE_BYTES;
        pCurPtrInNalu = nalu + H265_NALU_HEADER_SIZE_BYTES;

        while (remainingNaluLength != 0) {
            // TODO: Consider fragmenting into equal payload sizes.
            curPayloadSize = MIN(maxPayloadSize, remainingNaluLength);
            payloadSubLenSize++;
            payloadLength += H265_RTP_PAYLOAD_HEADER_SIZE_BYTES + H265_RTP_FU_HEADER_SIZE_BYTES + curPayloadSize;

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
                pPayload[H265_RTP_PAYLOAD_HEADER_SIZE_BYTES] = naluType;
                if (remainingNaluLength == naluLength - H265_NALU_HEADER_SIZE_BYTES) {
                    // Set for starting bit
                    pPayload[H265_RTP_PAYLOAD_HEADER_SIZE_BYTES] |= 0x1 << (H265_RTP_FU_HEADER_FU_TYPE_SIZE_BITS + 1);
                } else if (remainingNaluLength == curPayloadSize) {
                    // Set for ending bit
                    pPayload[H265_RTP_PAYLOAD_HEADER_SIZE_BYTES] |= 0x1 << H265_RTP_FU_HEADER_FU_TYPE_SIZE_BITS;
                }
                
                // Write the payload.
                MEMCPY(pPayload + H265_RTP_PAYLOAD_HEADER_SIZE_BYTES + H265_RTP_FU_HEADER_SIZE_BYTES, pCurPtrInNalu, curPayloadSize);

                pPayloadArray->payloadSubLength[payloadSubLenSize - 1] = H265_RTP_PAYLOAD_HEADER_SIZE_BYTES + H265_RTP_FU_HEADER_SIZE_BYTES + curPayloadSize;
                pPayload += pPayloadArray->payloadSubLength[payloadSubLenSize - 1];
            }

            pCurPtrInNalu += curPayloadSize;
            remainingNaluLength -= curPayloadSize;
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

STATUS depayH265FromRtpPayload(PBYTE pRawPacket, UINT32 packetLength, PBYTE pNaluData, PUINT32 pNaluLength, PBOOL pIsStart) {
    STATUS retStatus = STATUS_SUCCESS;

    // TODO: Implement de-payloading of SRST H.265 video transmissions.
    CHK(FALSE, STATUS_NOT_IMPLEMENTED);

CleanUp:
    LEAVES();
    return retStatus;
}
