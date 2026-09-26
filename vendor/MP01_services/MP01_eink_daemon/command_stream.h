#ifndef MP01_COMMAND_STREAM_H
#define MP01_COMMAND_STREAM_H

#include <stddef.h>

#define MP01_COMMAND_MAX_LENGTH 511

typedef void (*Mp01CommandCallback)(const char* command, void* context);

typedef struct {
    char command[MP01_COMMAND_MAX_LENGTH + 1];
    size_t length;
    int discarding;
} Mp01CommandStream;

void mp01CommandStreamInit(Mp01CommandStream* stream);
size_t mp01CommandStreamConsume(
        Mp01CommandStream* stream,
        const char* data,
        size_t dataLength,
        Mp01CommandCallback callback,
        void* context);
void mp01CommandStreamFinish(
        Mp01CommandStream* stream,
        Mp01CommandCallback callback,
        void* context);
void mp01CommandStreamDiscard(Mp01CommandStream* stream);

#endif
