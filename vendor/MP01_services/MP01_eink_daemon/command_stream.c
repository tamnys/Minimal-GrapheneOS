#include "command_stream.h"

static void emitCommand(
        Mp01CommandStream* stream,
        Mp01CommandCallback callback,
        void* context) {
    if (stream->length > 0 && stream->command[stream->length - 1] == '\r') {
        stream->length--;
    }

    if (stream->length > 0 && callback != NULL) {
        stream->command[stream->length] = '\0';
        callback(stream->command, context);
    }
    stream->length = 0;
}

void mp01CommandStreamInit(Mp01CommandStream* stream) {
    stream->length = 0;
    stream->discarding = 0;
}

size_t mp01CommandStreamConsume(
        Mp01CommandStream* stream,
        const char* data,
        size_t dataLength,
        Mp01CommandCallback callback,
        void* context) {
    size_t droppedCommands = 0;

    for (size_t index = 0; index < dataLength; index++) {
        const char value = data[index];
        if (value == '\n') {
            if (stream->discarding) {
                stream->discarding = 0;
                stream->length = 0;
            } else {
                emitCommand(stream, callback, context);
            }
            continue;
        }

        if (stream->discarding) {
            continue;
        }

        if (stream->length == MP01_COMMAND_MAX_LENGTH) {
            stream->length = 0;
            stream->discarding = 1;
            droppedCommands++;
            continue;
        }

        stream->command[stream->length++] = value;
    }

    return droppedCommands;
}

void mp01CommandStreamFinish(
        Mp01CommandStream* stream,
        Mp01CommandCallback callback,
        void* context) {
    if (!stream->discarding) {
        emitCommand(stream, callback, context);
    }
    mp01CommandStreamInit(stream);
}

void mp01CommandStreamDiscard(Mp01CommandStream* stream) {
    mp01CommandStreamInit(stream);
}
