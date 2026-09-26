#include "command_stream.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

#define CAPTURED_COMMANDS 8

typedef struct {
    char commands[CAPTURED_COMMANDS][MP01_COMMAND_MAX_LENGTH + 1];
    size_t count;
} Capture;

static void captureCommand(const char* command, void* context) {
    Capture* capture = context;
    assert(capture->count < CAPTURED_COMMANDS);
    strcpy(capture->commands[capture->count++], command);
}

static void testSplitAndCombinedFrames(void) {
    Mp01CommandStream stream;
    Capture capture = {0};
    mp01CommandStreamInit(&stream);

    assert(mp01CommandStreamConsume(&stream, "br_", 3, captureCommand, &capture) == 0);
    assert(mp01CommandStreamConsume(&stream, "co5\nr\n", 6, captureCommand, &capture) == 0);

    assert(capture.count == 2);
    assert(strcmp(capture.commands[0], "br_co5") == 0);
    assert(strcmp(capture.commands[1], "r") == 0);
}

static void testEofFlushAndCrLf(void) {
    Mp01CommandStream stream;
    Capture capture = {0};
    mp01CommandStreamInit(&stream);

    assert(mp01CommandStreamConsume(&stream, "c\r\ns", 4, captureCommand, &capture) == 0);
    mp01CommandStreamFinish(&stream, captureCommand, &capture);

    assert(capture.count == 2);
    assert(strcmp(capture.commands[0], "c") == 0);
    assert(strcmp(capture.commands[1], "s") == 0);
}

static void testOverflowDropsFrameAndRecovers(void) {
    Mp01CommandStream stream;
    Capture capture = {0};
    char oversized[MP01_COMMAND_MAX_LENGTH + 2];
    memset(oversized, 'x', sizeof(oversized));
    mp01CommandStreamInit(&stream);

    assert(mp01CommandStreamConsume(
            &stream, oversized, sizeof(oversized), captureCommand, &capture) == 1);
    assert(mp01CommandStreamConsume(
            &stream, "\nvalid\n\n", 8, captureCommand, &capture) == 0);

    assert(capture.count == 1);
    assert(strcmp(capture.commands[0], "valid") == 0);
}

static void testDiscardDropsIncompleteFrame(void) {
    Mp01CommandStream stream;
    Capture capture = {0};
    mp01CommandStreamInit(&stream);

    assert(mp01CommandStreamConsume(
            &stream, "br_co", 5, captureCommand, &capture) == 0);
    mp01CommandStreamDiscard(&stream);
    assert(mp01CommandStreamConsume(
            &stream, "r\n", 2, captureCommand, &capture) == 0);

    assert(capture.count == 1);
    assert(strcmp(capture.commands[0], "r") == 0);
}

int main(void) {
    testSplitAndCombinedFrames();
    testEofFlushAndCrLf();
    testOverflowDropsFrameAndRecovers();
    testDiscardDropsIncompleteFrame();
    puts("MP01 command stream tests passed");
    return 0;
}
