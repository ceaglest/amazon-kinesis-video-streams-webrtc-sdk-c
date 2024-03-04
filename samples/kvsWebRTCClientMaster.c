#include "Samples.h"

extern PSampleConfiguration gSampleConfiguration;

INT32 main(INT32 argc, CHAR* argv[])
{
    STATUS retStatus = STATUS_SUCCESS;
    UINT32 frameSize;
    PSampleConfiguration pSampleConfiguration = NULL;
    PCHAR pChannelName;
    SignalingClientMetrics signalingClientMetrics;
    signalingClientMetrics.version = SIGNALING_CLIENT_METRICS_CURRENT_VERSION;

    SET_INSTRUMENTED_ALLOCATORS();
    UINT32 logLevel = setLogLevel();

#ifndef _WIN32
    signal(SIGINT, sigintHandler);
#endif

#ifdef IOT_CORE_ENABLE_CREDENTIALS
    CHK_ERR((pChannelName = getenv(IOT_CORE_THING_NAME)) != NULL, STATUS_INVALID_OPERATION, "AWS_IOT_CORE_THING_NAME must be set");
#else
    pChannelName = argc > 1 ? argv[1] : SAMPLE_CHANNEL_NAME;
#endif

    CHK_STATUS(createSampleConfiguration(pChannelName, SIGNALING_CHANNEL_ROLE_TYPE_MASTER, TRUE, TRUE, logLevel, &pSampleConfiguration));

    // Set the audio and video handlers
    // TODO: Add a command line argument or environment variable to locate the bitstream.
    bool useH265 = SAMPLE_ENABLE_H265_VIDEO;
    pSampleConfiguration->audioSource = sendAudioPackets;
    if (useH265) {
        pSampleConfiguration->videoSource = sendH265VideoPackets;
    } else {
        pSampleConfiguration->videoSource = sendH264VideoPackets;
    }
    pSampleConfiguration->receiveAudioVideoSource = sampleReceiveAudioVideoFrame;

    if (argc > 2 && STRNCMP(argv[2], "1", 2) == 0) {
        CHK_ERR(!useH265, STATUS_NULL_ARG, "[KVS Master] Storing H.265 video is not supported.");
        pSampleConfiguration->channelInfo.useMediaStorage = TRUE;
    }

#ifdef ENABLE_DATA_CHANNEL
    pSampleConfiguration->onDataChannel = onDataChannel;
#endif
    pSampleConfiguration->mediaType = SAMPLE_STREAMING_AUDIO_VIDEO;
    DLOGI("[KVS Master] Finished setting handlers");

    // Check if the samples are present
    if (useH265) {
        CHK_STATUS(readFrameFromDisk(NULL, &frameSize, SAMPLE_DEFAULT_H265_BITSTREAM_PATH));
    } else {
        CHAR filePath[MAX_PATH_LEN + 1];
        SNPRINTF(filePath, MAX_PATH_LEN, SAMPLE_DEFAULT_H264_FRAME_PATTERN, 1);
        CHK_STATUS(readFrameFromDisk(NULL, &frameSize, filePath));
    }
    DLOGI("[KVS Master] Checked sample video frame availability....available");

    CHAR opusFilePath[MAX_PATH_LEN + 1];
    SNPRINTF(opusFilePath, MAX_PATH_LEN, SAMPLE_DEFAULT_OPUS_FRAME_PATTERN, 0);
    CHK_STATUS(readFrameFromDisk(NULL, &frameSize, opusFilePath));
    DLOGI("[KVS Master] Checked sample audio frame availability....available");

    // Initialize KVS WebRTC. This must be done before anything else, and must only be done once.
    CHK_STATUS(initKvsWebRtc());
    DLOGI("[KVS Master] KVS WebRTC initialization completed successfully");

    CHK_STATUS(initSignaling(pSampleConfiguration, SAMPLE_MASTER_CLIENT_ID));
    DLOGI("[KVS Master] Channel %s set up done ", pChannelName);

    // Checking for termination
    CHK_STATUS(sessionCleanupWait(pSampleConfiguration));
    DLOGI("[KVS Master] Streaming session terminated");

CleanUp:

    if (retStatus != STATUS_SUCCESS) {
        DLOGE("[KVS Master] Terminated with status code 0x%08x", retStatus);
    }

    DLOGI("[KVS Master] Cleaning up....");
    if (pSampleConfiguration != NULL) {
        // Kick of the termination sequence
        ATOMIC_STORE_BOOL(&pSampleConfiguration->appTerminateFlag, TRUE);

        if (pSampleConfiguration->mediaSenderTid != INVALID_TID_VALUE) {
            THREAD_JOIN(pSampleConfiguration->mediaSenderTid, NULL);
        }

        retStatus = signalingClientGetMetrics(pSampleConfiguration->signalingClientHandle, &signalingClientMetrics);
        if (retStatus == STATUS_SUCCESS) {
            logSignalingClientStats(&signalingClientMetrics);
        } else {
            DLOGE("[KVS Master] signalingClientGetMetrics() operation returned status code: 0x%08x", retStatus);
        }
        retStatus = freeSignalingClient(&pSampleConfiguration->signalingClientHandle);
        if (retStatus != STATUS_SUCCESS) {
            DLOGE("[KVS Master] freeSignalingClient(): operation returned status code: 0x%08x", retStatus);
        }

        retStatus = freeSampleConfiguration(&pSampleConfiguration);
        if (retStatus != STATUS_SUCCESS) {
            DLOGE("[KVS Master] freeSampleConfiguration(): operation returned status code: 0x%08x", retStatus);
        }
    }
    DLOGI("[KVS Master] Cleanup done");
    CHK_LOG_ERR(retStatus);

    RESET_INSTRUMENTED_ALLOCATORS();

    // https://www.gnu.org/software/libc/manual/html_node/Exit-Status.html
    // We can only return with 0 - 127. Some platforms treat exit code >= 128
    // to be a success code, which might give an unintended behaviour.
    // Some platforms also treat 1 or 0 differently, so it's better to use
    // EXIT_FAILURE and EXIT_SUCCESS macros for portability.
    return STATUS_FAILED(retStatus) ? EXIT_FAILURE : EXIT_SUCCESS;
}

STATUS readFrameFromDisk(PBYTE pFrame, PUINT32 pSize, PCHAR frameFilePath)
{
    STATUS retStatus = STATUS_SUCCESS;
    UINT64 size = 0;
    CHK_ERR(pSize != NULL, STATUS_NULL_ARG, "[KVS Master] Invalid file size");
    size = *pSize;
    // Get the size and read into frame
    CHK_STATUS(readFile(frameFilePath, TRUE, pFrame, &size));
CleanUp:

    if (pSize != NULL) {
        *pSize = (UINT32) size;
    }

    return retStatus;
}

PVOID sendH264VideoPackets(PVOID args)
{
    STATUS retStatus = STATUS_SUCCESS;
    PSampleConfiguration pSampleConfiguration = (PSampleConfiguration) args;
    RtcEncoderStats encoderStats;
    Frame frame;
    UINT32 fileIndex = 0, frameSize;
    CHAR filePath[MAX_PATH_LEN + 1];
    STATUS status;
    UINT32 i;
    UINT64 startTime, lastFrameTime, elapsed;
    MEMSET(&encoderStats, 0x00, SIZEOF(RtcEncoderStats));
    CHK_ERR(pSampleConfiguration != NULL, STATUS_NULL_ARG, "[KVS Master] Streaming session is NULL");

    frame.presentationTs = 0;
    startTime = GETTIME();
    lastFrameTime = startTime;

    while (!ATOMIC_LOAD_BOOL(&pSampleConfiguration->appTerminateFlag)) {
        fileIndex = fileIndex % NUMBER_OF_H264_FRAME_FILES + 1;
        SNPRINTF(filePath, MAX_PATH_LEN, SAMPLE_DEFAULT_H264_FRAME_PATTERN, fileIndex);

        CHK_STATUS(readFrameFromDisk(NULL, &frameSize, filePath));

        // Re-alloc if needed
        if (frameSize > pSampleConfiguration->videoBufferSize) {
            pSampleConfiguration->pVideoFrameBuffer = (PBYTE) MEMREALLOC(pSampleConfiguration->pVideoFrameBuffer, frameSize);
            CHK_ERR(pSampleConfiguration->pVideoFrameBuffer != NULL, STATUS_NOT_ENOUGH_MEMORY, "[KVS Master] Failed to allocate video frame buffer");
            pSampleConfiguration->videoBufferSize = frameSize;
        }

        frame.frameData = pSampleConfiguration->pVideoFrameBuffer;
        frame.size = frameSize;

        CHK_STATUS(readFrameFromDisk(frame.frameData, &frameSize, filePath));

        // based on bitrate of samples/h264SampleFrames/frame-*
        encoderStats.width = 640;
        encoderStats.height = 480;
        encoderStats.targetBitrate = 262000;
        frame.presentationTs += SAMPLE_VIDEO_FRAME_DURATION;
        MUTEX_LOCK(pSampleConfiguration->streamingSessionListReadLock);
        for (i = 0; i < pSampleConfiguration->streamingSessionCount; ++i) {
            status = writeFrame(pSampleConfiguration->sampleStreamingSessionList[i]->pVideoRtcRtpTransceiver, &frame);
            if (pSampleConfiguration->sampleStreamingSessionList[i]->firstFrame && status == STATUS_SUCCESS) {
                PROFILE_WITH_START_TIME(pSampleConfiguration->sampleStreamingSessionList[i]->offerReceiveTime, "Time to first frame");
                pSampleConfiguration->sampleStreamingSessionList[i]->firstFrame = FALSE;
            }
            encoderStats.encodeTimeMsec = 4; // update encode time to an arbitrary number to demonstrate stats update
            updateEncoderStats(pSampleConfiguration->sampleStreamingSessionList[i]->pVideoRtcRtpTransceiver, &encoderStats);
            if (status != STATUS_SRTP_NOT_READY_YET) {
                if (status != STATUS_SUCCESS) {
                    DLOGV("writeFrame() failed with 0x%08x", status);
                }
            }
        }
        MUTEX_UNLOCK(pSampleConfiguration->streamingSessionListReadLock);

        // Adjust sleep in the case the sleep itself and writeFrame take longer than expected. Since sleep makes sure that the thread
        // will be paused at least until the given amount, we can assume that there's no too early frame scenario.
        // Also, it's very unlikely to have a delay greater than SAMPLE_VIDEO_FRAME_DURATION, so the logic assumes that this is always
        // true for simplicity.
        elapsed = lastFrameTime - startTime;
        THREAD_SLEEP(SAMPLE_VIDEO_FRAME_DURATION - elapsed % SAMPLE_VIDEO_FRAME_DURATION);
        lastFrameTime = GETTIME();
    }

CleanUp:
    DLOGI("[KVS Master] Closing H.264 video thread");
    CHK_LOG_ERR(retStatus);

    return (PVOID) (ULONG_PTR) retStatus;
}

// TODO: Declaring a private function. Could it be made available directly to developers?
STATUS getNextNaluLength(PBYTE nalus, UINT32 nalusLength, PUINT32 pStart, PUINT32 pNaluLength);
#define H265_NALU_TYPE_AUD_NUT (UINT8)35
#define H265_NALU_TYPE_EOS_NUT (UINT8)36
#define H265_NALU_TYPE_EOB_NUT (UINT8)37

/*
 * Find the end of the Access Unit (AU) and pass the entire AU as a frame.
 * Note: Access Unit Delimiters are required to be placed in the bitstream.
 *
 * Examples
 * --------
 *
 * Instantaneous Decoder Refresh (IDR) with an Access Unit Delimiter (AUD)
 * [ [AUD] [VPS] [SPS] [PPS] [SEI] [IDR] ] [ [AUD] ... ] ...
 *
 * Predicted (P) with a delimiter
 * .. [ [AUD] [P] ] [ [AUD] ... ] ...
 *
 * End of sequence.
 * .. [ [ AUD ] [ P ] ] [ EOS ] [ [ AUD ] [ VPS ] [ SPS ] [ PPS ] [ IDR ] ] ...
 *
 */
STATUS getNextH265AccessUnitLength(PBYTE nalus, UINT32 nalusLength, PUINT32 pStart, PUINT32 pNaluLength)
{
    STATUS retStatus = STATUS_SUCCESS;
    PBYTE curPtrInNalus = nalus;
    UINT32 remainNalusLength = nalusLength;
    UINT32 nextNaluLength = 0;
    UINT32 accessUnitLength = 0;
    UINT32 startIndex = 0;
    bool endOfAccessUnit = false;
    bool startOfAccessUnit = false;

    do {
        CHK_STATUS(getNextNaluLength(curPtrInNalus, remainNalusLength, &startIndex, &nextNaluLength));
        
        /*
         * Parse the type of the NALU from the header for basic seeking using delimiters.
         */
        UINT8 nalUnitTypeMask = (UINT8) 0x7E;
        UINT8 naluType = (*(curPtrInNalus + startIndex) & nalUnitTypeMask) >> 1;
        if (naluType == H265_NALU_TYPE_AUD_NUT) {
            if (startOfAccessUnit) {
                // Second AUD ends the first AU.
                endOfAccessUnit = true;
            } else {
                startOfAccessUnit = true;
            }
        } else if (naluType == H265_NALU_TYPE_EOS_NUT || naluType == H265_NALU_TYPE_EOB_NUT) {
            endOfAccessUnit = true;
        }

        if (!endOfAccessUnit) {
            curPtrInNalus += startIndex + nextNaluLength;
            remainNalusLength -= startIndex + nextNaluLength;
            accessUnitLength += startIndex + nextNaluLength;
        }
    } while (!endOfAccessUnit && remainNalusLength > 0);

    *pStart = 0;
    *pNaluLength = accessUnitLength;
    return (PVOID) (ULONG_PTR) retStatus;

CleanUp:
    DLOGI("[KVS Master] Failed to parse H.265 access unit.");
    CHK_LOG_ERR(retStatus);
    *pStart = 0;
    *pNaluLength = 0;

    return (PVOID) (ULONG_PTR) retStatus;
}

PVOID sendH265VideoPackets(PVOID args)
{
    STATUS retStatus = STATUS_SUCCESS;
    PSampleConfiguration pSampleConfiguration = (PSampleConfiguration) args;
    RtcEncoderStats encoderStats;
    Frame h265AnnexB;
    Frame accessUnit;
    UINT32 bitstreamSize;
    STATUS status;
    UINT32 i;
    UINT64 startTime, lastFrameTime, elapsed;
    MEMSET(&encoderStats, 0x00, SIZEOF(RtcEncoderStats));
    CHK_ERR(pSampleConfiguration != NULL, STATUS_NULL_ARG, "[KVS Master] Streaming session is NULL");

    accessUnit.presentationTs = 0;
    startTime = GETTIME();
    lastFrameTime = startTime;

    // Read the entire bitstream into memory (re-alloc if needed).
    CHK_STATUS(readFrameFromDisk(NULL, &bitstreamSize, SAMPLE_DEFAULT_H265_BITSTREAM_PATH));

    if (bitstreamSize > pSampleConfiguration->videoBufferSize) {
        pSampleConfiguration->pVideoFrameBuffer = (PBYTE) MEMREALLOC(pSampleConfiguration->pVideoFrameBuffer, bitstreamSize);
        CHK_ERR(pSampleConfiguration->pVideoFrameBuffer != NULL, STATUS_NOT_ENOUGH_MEMORY, "[KVS Master] Failed to allocate video frame buffer");
        pSampleConfiguration->videoBufferSize = bitstreamSize;
    }

    h265AnnexB.frameData = pSampleConfiguration->pVideoFrameBuffer;
    h265AnnexB.size = bitstreamSize;

    CHK_STATUS(readFrameFromDisk(h265AnnexB.frameData, &bitstreamSize, SAMPLE_DEFAULT_H265_BITSTREAM_PATH));
    
    // TODO: Determine the encoder stats by the non-VCL NALUs, by filename convention or by a .csv manifest.
    // based on bitrate of samples/h265SampleBitstreams/sample.h265*
    UINT16 width = SAMPLE_H265_VIDEO_FRAME_WIDTH;
    UINT16 height = SAMPLE_H265_VIDEO_FRAME_HEIGHT;
    UINT16 bitDepth = SAMPLE_H265_VIDEO_BIT_DEPTH;
    UINT32 targetBitrate = SAMPLE_H265_VIDEO_TARGET_BITRATE;

    while (!ATOMIC_LOAD_BOOL(&pSampleConfiguration->appTerminateFlag)) {
        encoderStats.width = width;
        encoderStats.height = height;
        encoderStats.bitDepth = bitDepth;
        encoderStats.targetBitrate = targetBitrate;

        UINT32 pStart; UINT32 pNaluLength;
        CHK_STATUS(getNextH265AccessUnitLength(h265AnnexB.frameData, h265AnnexB.size, &pStart, &pNaluLength));
        accessUnit.size = pNaluLength;
        accessUnit.frameData = h265AnnexB.frameData + pStart;
        accessUnit.duration = SAMPLE_H265_VIDEO_FRAME_DURATION;
        accessUnit.presentationTs += SAMPLE_H265_VIDEO_FRAME_DURATION;
        
        MUTEX_LOCK(pSampleConfiguration->streamingSessionListReadLock);
        for (i = 0; i < pSampleConfiguration->streamingSessionCount; ++i) {
            status = writeFrame(pSampleConfiguration->sampleStreamingSessionList[i]->pVideoRtcRtpTransceiver, &accessUnit);
            if (pSampleConfiguration->sampleStreamingSessionList[i]->firstFrame && status == STATUS_SUCCESS) {
                PROFILE_WITH_START_TIME(pSampleConfiguration->sampleStreamingSessionList[i]->offerReceiveTime, "Time to first frame");
                pSampleConfiguration->sampleStreamingSessionList[i]->firstFrame = FALSE;
            }
            encoderStats.encodeTimeMsec = 4; // update encode time to an arbitrary number to demonstrate stats update
            updateEncoderStats(pSampleConfiguration->sampleStreamingSessionList[i]->pVideoRtcRtpTransceiver, &encoderStats);
            if (status != STATUS_SRTP_NOT_READY_YET) {
                if (status != STATUS_SUCCESS) {
                    DLOGV("writeFrame() failed with 0x%08x", status);
                }
            }
        }
        MUTEX_UNLOCK(pSampleConfiguration->streamingSessionListReadLock);

        // Advance the bitstream cursor by one access unit.
        h265AnnexB.frameData += pStart + pNaluLength;
        h265AnnexB.size -= pStart + pNaluLength;

        // Adjust sleep in the case the sleep itself and writeFrame take longer than expected. Since sleep makes sure that the thread
        // will be paused at least until the given amount, we can assume that there's no too early frame scenario.
        // Also, it's very unlikely to have a delay greater than SAMPLE_VIDEO_FRAME_DURATION, so the logic assumes that this is always
        // true for simplicity.
        elapsed = lastFrameTime - startTime;
        THREAD_SLEEP(SAMPLE_H265_VIDEO_FRAME_DURATION - elapsed % SAMPLE_H265_VIDEO_FRAME_DURATION);
        lastFrameTime = GETTIME();
    }

CleanUp:
    DLOGI("[KVS Master] Closing H.265 video thread");
    CHK_LOG_ERR(retStatus);

    return (PVOID) (ULONG_PTR) retStatus;
}

PVOID sendAudioPackets(PVOID args)
{
    STATUS retStatus = STATUS_SUCCESS;
    PSampleConfiguration pSampleConfiguration = (PSampleConfiguration) args;
    Frame frame;
    UINT32 fileIndex = 0, frameSize;
    CHAR filePath[MAX_PATH_LEN + 1];
    UINT32 i;
    STATUS status;

    CHK_ERR(pSampleConfiguration != NULL, STATUS_NULL_ARG, "[KVS Master] Streaming session is NULL");
    frame.presentationTs = 0;

    while (!ATOMIC_LOAD_BOOL(&pSampleConfiguration->appTerminateFlag)) {
        fileIndex = fileIndex % NUMBER_OF_OPUS_FRAME_FILES + 1;
        SNPRINTF(filePath, MAX_PATH_LEN, SAMPLE_DEFAULT_OPUS_FRAME_PATTERN, fileIndex);

        CHK_STATUS(readFrameFromDisk(NULL, &frameSize, filePath));

        // Re-alloc if needed
        if (frameSize > pSampleConfiguration->audioBufferSize) {
            pSampleConfiguration->pAudioFrameBuffer = (UINT8*) MEMREALLOC(pSampleConfiguration->pAudioFrameBuffer, frameSize);
            CHK_ERR(pSampleConfiguration->pAudioFrameBuffer != NULL, STATUS_NOT_ENOUGH_MEMORY, "[KVS Master] Failed to allocate audio frame buffer");
            pSampleConfiguration->audioBufferSize = frameSize;
        }

        frame.frameData = pSampleConfiguration->pAudioFrameBuffer;
        frame.size = frameSize;

        CHK_STATUS(readFrameFromDisk(frame.frameData, &frameSize, filePath));

        frame.presentationTs += SAMPLE_AUDIO_FRAME_DURATION;

        MUTEX_LOCK(pSampleConfiguration->streamingSessionListReadLock);
        for (i = 0; i < pSampleConfiguration->streamingSessionCount; ++i) {
            status = writeFrame(pSampleConfiguration->sampleStreamingSessionList[i]->pAudioRtcRtpTransceiver, &frame);
            if (status != STATUS_SRTP_NOT_READY_YET) {
                if (status != STATUS_SUCCESS) {
                    DLOGV("writeFrame() failed with 0x%08x", status);
                } else if (pSampleConfiguration->sampleStreamingSessionList[i]->firstFrame && status == STATUS_SUCCESS) {
                    PROFILE_WITH_START_TIME(pSampleConfiguration->sampleStreamingSessionList[i]->offerReceiveTime, "Time to first frame");
                    pSampleConfiguration->sampleStreamingSessionList[i]->firstFrame = FALSE;
                }
            }
        }
        MUTEX_UNLOCK(pSampleConfiguration->streamingSessionListReadLock);
        THREAD_SLEEP(SAMPLE_AUDIO_FRAME_DURATION);
    }

CleanUp:
    DLOGI("[KVS Master] closing audio thread");
    return (PVOID) (ULONG_PTR) retStatus;
}

PVOID sampleReceiveAudioVideoFrame(PVOID args)
{
    STATUS retStatus = STATUS_SUCCESS;
    PSampleStreamingSession pSampleStreamingSession = (PSampleStreamingSession) args;
    CHK_ERR(pSampleStreamingSession != NULL, STATUS_NULL_ARG, "[KVS Master] Streaming session is NULL");
    CHK_STATUS(transceiverOnFrame(pSampleStreamingSession->pVideoRtcRtpTransceiver, (UINT64) pSampleStreamingSession, sampleVideoFrameHandler));
    CHK_STATUS(transceiverOnFrame(pSampleStreamingSession->pAudioRtcRtpTransceiver, (UINT64) pSampleStreamingSession, sampleAudioFrameHandler));

CleanUp:

    return (PVOID) (ULONG_PTR) retStatus;
}
