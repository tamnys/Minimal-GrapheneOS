#include "command_dispatch.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    const char* name;
    const char* value;
    int calls;
    int succeed;
} Capture;

static int captureWrite(const char* name, const char* value, void* context) {
    Capture* capture = context;
    capture->name = name;
    capture->value = value;
    capture->calls++;
    return capture->succeed;
}

static Mp01CommandOperations operationsFor(Capture* capture) {
    return (Mp01CommandOperations) {
        .write_node = captureWrite,
        .set_property = captureWrite,
        .context = capture,
    };
}

static void testNodeWriteResult(void) {
    Capture capture = {.succeed = 1};
    Mp01CommandOperations operations = operationsFor(&capture);
    const struct {
        const char* command;
        const char* path;
        const char* value;
    } cases[] = {
        {"cm", "/sys/devices/platform/soc/soc:qcom,dsi-display-primary/epd_commit_bitmap", "1"},
        {"r", "/sys/devices/platform/soc/11f00000.i2c/i2c-7/7-004b/eink_cpld_registers", "5"},
        {"c", "/sys/devices/platform/soc/11f00000.i2c/i2c-7/7-004b/eink_cpld_registers", "2"},
        {"b", "/sys/devices/platform/soc/11f00000.i2c/i2c-7/7-004b/eink_cpld_registers", "1"},
        {"s", "/sys/devices/platform/soc/11f00000.i2c/i2c-7/7-004b/eink_cpld_registers", "3"},
        {"p", "/sys/devices/platform/soc/11f00000.i2c/i2c-7/7-004b/eink_cpld_registers", "4"},
        {"stw7", "/sys/devices/platform/soc/soc:qcom,dsi-display-primary/epd_white_threshold", "7"},
        {"stb8", "/sys/devices/platform/soc/soc:qcom,dsi-display-primary/epd_black_threshold", "8"},
        {"sco9", "/sys/devices/platform/soc/soc:qcom,dsi-display-primary/epd_contrast", "9"},
        {"br_co42", "/sys/class/leds/lcd-backlight/brightness", "42"},
        {"br_wm43", "/sys/class/leds/led-warmlight/brightness", "43"},
        {"br_kb44", "/sys/class/leds/keyboard-backlight/brightness", "44"},
    };
    for (size_t index = 0; index < sizeof(cases) / sizeof(cases[0]); index++) {
        assert(mp01DispatchCommand(cases[index].command, &operations) == MP01_COMMAND_APPLIED);
        assert(strcmp(capture.name, cases[index].path) == 0);
        assert(strcmp(capture.value, cases[index].value) == 0);
    }
    assert(capture.calls == (int)(sizeof(cases) / sizeof(cases[0])));

    capture.succeed = 0;
    assert(mp01DispatchCommand("r", &operations) == MP01_COMMAND_FAILED);
    assert(capture.calls == (int)(sizeof(cases) / sizeof(cases[0])) + 1);
    assert(strcmp(capture.value, "5") == 0);
}

static void testPropertyIsOnlyAccepted(void) {
    Capture capture = {.succeed = 1};
    Mp01CommandOperations operations = operationsFor(&capture);
    assert(mp01DispatchCommand("au_br1", &operations) == MP01_COMMAND_ACCEPTED);
    assert(strcmp(capture.name, "sys.mp01.eink.clean_a2") == 0);
    assert(strcmp(capture.value, "1") == 0);
    assert(mp01DispatchCommand("au_br0", &operations) == MP01_COMMAND_ACCEPTED);
    assert(strcmp(capture.value, "0") == 0);
    assert(mp01DispatchCommand("an_fl0", &operations) == MP01_COMMAND_ACCEPTED);
    assert(strcmp(capture.name, "sys.mp01.eink.anti_flicker") == 0);
    assert(mp01DispatchCommand("an_fl1", &operations) == MP01_COMMAND_ACCEPTED);
    assert(strcmp(capture.value, "1") == 0);

    capture.succeed = 0;
    assert(mp01DispatchCommand("an_fl1", &operations) == MP01_COMMAND_FAILED);
}

static void testInvalidCommandsCannotReachHardware(void) {
    Capture capture = {.succeed = 1};
    Mp01CommandOperations operations = operationsFor(&capture);
    const char* invalid[] = {
        "", "br_co", "br_co-1", "br_co99999", "au_br1x", "unknown",
        "au_br", "au_br2", "au_br01", "au_br9999",
        "an_fl", "an_fl2", "an_fl01", "an_fl9999",
    };
    for (size_t index = 0; index < sizeof(invalid) / sizeof(invalid[0]); index++) {
        assert(mp01DispatchCommand(invalid[index], &operations) == MP01_COMMAND_FAILED);
    }
    assert(capture.calls == 0);
}

int main(void) {
    testNodeWriteResult();
    testPropertyIsOnlyAccepted();
    testInvalidCommandsCannotReachHardware();
    puts("MP01 command dispatch tests passed");
    return 0;
}
