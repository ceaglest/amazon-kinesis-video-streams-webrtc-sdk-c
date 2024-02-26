#define LOG_CLASS "RtpH265Payloader"

#include "../../Include_i.h"

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

STATUS createH265PayloadFromNalu(UINT32 mtu, PBYTE nalu, UINT32 naluLength, PPayloadArray pPayloadArray, PUINT32 filledLength, PUINT32 filledSubLenSize)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PBYTE pPayload = NULL;
    UINT8 naluType = 0;
    UINT8 nuhLayerId = 0;
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
    CHK(mtu > H265_RTP_PAYLOAD_HEADER_SIZE, STATUS_RTP_INPUT_MTU_TOO_SMALL);

    // TODO: Parse nuh_layer_id and nuh_temporal_id_plus1.
    /*
     nal_unit_header {
       forbidden_zero_bit: 0
       nal_unit_type: 32
       nuh_layer_id: 0
       nuh_temporal_id_plus1: 1
     }
     * forbidden_zero_bit  f(1)
     * nal_unit_type  u(6)
     * nuh_layer_id  u(6)
     * nuh_temporal_id_plus1  u(3)
     */
    naluType = (*nalu & H265_NALU_HEADER_NAL_UNIT_TYPE_MASK) >> 1;

    if (!sizeCalculationOnly) {
        pPayload = pPayloadArray->payloadBuffer;
    }

    // TODO: Consider using Aggregation Packets for non-VCL NALUs
    if (naluLength <= mtu) {
        // Single NALU: https://datatracker.ietf.org/doc/html/rfc7798#section-4.4.1
        payloadLength += naluLength;
        payloadSubLenSize++;

        if (!sizeCalculationOnly) {
            CHK(payloadSubLenSize <= pPayloadArray->maxPayloadSubLenSize && payloadLength <= pPayloadArray->maxPayloadLength,
                STATUS_BUFFER_TOO_SMALL);

            // Single NALU https://tools.ietf.org/html/rfc7798#section-4.4.1
            // The DONL field is not present because the library does not negotiate frame reordering.
            MEMCPY(pPayload, nalu, naluLength);
            pPayloadArray->payloadSubLength[payloadSubLenSize - 1] = naluLength;
            pPayload += pPayloadArray->payloadSubLength[payloadSubLenSize - 1];
        }
    } else {
        // FU: https://tools.ietf.org/html/rfc7798#section-4.4.3
        maxPayloadSize = mtu - H265_RTP_PAYLOAD_HEADER_SIZE - H265_RTP_FU_HEADER_SIZE;
        
        /*
         * Construct the PayloadHdr common to each packet.
         *
         * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6
         * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         * |    PayloadHdr (Type=49)       |
         * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         */
        UINT8 payloadHdr[H265_RTP_PAYLOAD_HEADER_SIZE];
        // F, LayerId, and TID MUST be equal to the original NAL
        memcpy(&payloadHdr, nalu, H265_NALU_HEADER_SIZE);
        // The Type field must be 49
        payloadHdr[0] |= ((H265_RTP_FU_PAYLOAD_HEADER_TYPE << 1) ^ H265_NALU_HEADER_NAL_UNIT_TYPE_MASK);

        // The FU header contains equivalent information to the NALU header. It is removed.
        remainingNaluLength -= H265_NALU_HEADER_SIZE;
        pCurPtrInNalu = nalu + H265_NALU_HEADER_SIZE;

        while (remainingNaluLength != 0) {
            curPayloadSize = MIN(maxPayloadSize, remainingNaluLength);
            payloadSubLenSize++;
            payloadLength += H265_RTP_PAYLOAD_HEADER_SIZE + H265_RTP_FU_HEADER_SIZE + curPayloadSize;

            if (!sizeCalculationOnly) {
                CHK(payloadSubLenSize <= pPayloadArray->maxPayloadSubLenSize && payloadLength <= pPayloadArray->maxPayloadLength,
                    STATUS_BUFFER_TOO_SMALL);
                /*
                 * Write the common PayloadHdr.
                 * Note: The DONL field is skipped when sprop-max-don-diff == 0.
                 */
                MEMCPY(pPayload, payloadHdr, H265_RTP_PAYLOAD_HEADER_SIZE);

                /*
                 * Write the FU header.
                 * +---------------+
                 * |0|1|2|3|4|5|6|7|
                 * +-+-+-+-+-+-+-+-+
                 * |S|E|  FuType   |
                 * +---------------+
                 */
                pPayload[2] = naluType;
                if (remainingNaluLength == naluLength - 1) {
                    // Set for starting bit
                    pPayload[H265_RTP_PAYLOAD_HEADER_SIZE] |= 1 << (H265_RTP_FU_HEADER_FU_TYPE_BITS + 1);
                } else if (remainingNaluLength == curPayloadSize) {
                    // Set for ending bit
                    pPayload[H265_RTP_PAYLOAD_HEADER_SIZE] |= 1 << H265_RTP_FU_HEADER_FU_TYPE_BITS;
                }
                MEMCPY(pPayload + H265_RTP_PAYLOAD_HEADER_SIZE + H265_RTP_FU_HEADER_SIZE, pCurPtrInNalu, curPayloadSize);

                pPayloadArray->payloadSubLength[payloadSubLenSize - 1] = H265_RTP_PAYLOAD_HEADER_SIZE + H265_RTP_FU_HEADER_SIZE + curPayloadSize;
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
