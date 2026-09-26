#include "command_dispatch.h"

#include <stddef.h>
#include <string.h>

#define COLD_BACKLIGHT_PATH "/sys/class/leds/lcd-backlight/brightness"
#define WARM_BACKLIGHT_PATH "/sys/class/leds/led-warmlight/brightness"
#define KEYBOARD_BACKLIGHT_PATH "/sys/class/leds/keyboard-backlight/brightness"
#define EPD_CPLD_REGISTERS_PATH "/sys/devices/platform/soc/11f00000.i2c/i2c-7/7-004b/eink_cpld_registers"
#define EPD_COMMIT_BITMAP_PATH "/sys/devices/platform/soc/soc:qcom,dsi-display-primary/epd_commit_bitmap"
#define WHITE_THRESHOLD_PATH "/sys/devices/platform/soc/soc:qcom,dsi-display-primary/epd_white_threshold"
#define BLACK_THRESHOLD_PATH "/sys/devices/platform/soc/soc:qcom,dsi-display-primary/epd_black_threshold"
#define CONTRAST_PATH "/sys/devices/platform/soc/soc:qcom,dsi-display-primary/epd_contrast"
#define GLOBAL_AUTO_REFRESH_PROPERTY "sys.mp01.eink.clean_a2"
#define ANTI_FLICKER_PROPERTY "sys.mp01.eink.anti_flicker"

static int validNumber(const char* value) {
    size_t length = strlen(value);
    if (length == 0 || length > 4) {
        return 0;
    }
    for (size_t index = 0; index < length; index++) {
        if (value[index] < '0' || value[index] > '9') {
            return 0;
        }
    }
    return 1;
}

static Mp01CommandResult writeNode(
        const Mp01CommandOperations* operations, const char* path, const char* value) {
    return operations->write_node(path, value, operations->context)
            ? MP01_COMMAND_APPLIED : MP01_COMMAND_FAILED;
}

static Mp01CommandResult writeNumber(
        const Mp01CommandOperations* operations, const char* path, const char* value) {
    return validNumber(value) ? writeNode(operations, path, value) : MP01_COMMAND_FAILED;
}

static Mp01CommandResult setProperty(
        const Mp01CommandOperations* operations, const char* name, const char* value) {
    /* Only the existing tested 0/1 command forms are accepted until the
     * device's debugfs semantics have been measured. */
    if (strcmp(value, "0") != 0 && strcmp(value, "1") != 0) {
        return MP01_COMMAND_FAILED;
    }
    /* Property-service success cannot establish that init wrote the node. */
    return operations->set_property(name, value, operations->context)
            ? MP01_COMMAND_ACCEPTED : MP01_COMMAND_FAILED;
}

Mp01CommandResult mp01DispatchCommand(
        const char* command, const Mp01CommandOperations* operations) {
    if (command == NULL || operations == NULL || operations->write_node == NULL
            || operations->set_property == NULL) {
        return MP01_COMMAND_FAILED;
    }
    if (strcmp(command, "cm") == 0) {
        return writeNode(operations, EPD_COMMIT_BITMAP_PATH, "1");
    }
    if (strcmp(command, "r") == 0) {
        return writeNode(operations, EPD_CPLD_REGISTERS_PATH, "5");
    }
    if (strcmp(command, "c") == 0) {
        return writeNode(operations, EPD_CPLD_REGISTERS_PATH, "2");
    }
    if (strcmp(command, "b") == 0) {
        return writeNode(operations, EPD_CPLD_REGISTERS_PATH, "1");
    }
    if (strcmp(command, "s") == 0) {
        return writeNode(operations, EPD_CPLD_REGISTERS_PATH, "3");
    }
    if (strcmp(command, "p") == 0) {
        return writeNode(operations, EPD_CPLD_REGISTERS_PATH, "4");
    }
    if (strncmp(command, "stw", 3) == 0) {
        return writeNumber(operations, WHITE_THRESHOLD_PATH, command + 3);
    }
    if (strncmp(command, "stb", 3) == 0) {
        return writeNumber(operations, BLACK_THRESHOLD_PATH, command + 3);
    }
    if (strncmp(command, "sco", 3) == 0) {
        return writeNumber(operations, CONTRAST_PATH, command + 3);
    }
    if (strncmp(command, "br_co", 5) == 0) {
        return writeNumber(operations, COLD_BACKLIGHT_PATH, command + 5);
    }
    if (strncmp(command, "br_wm", 5) == 0) {
        return writeNumber(operations, WARM_BACKLIGHT_PATH, command + 5);
    }
    if (strncmp(command, "br_kb", 5) == 0) {
        return writeNumber(operations, KEYBOARD_BACKLIGHT_PATH, command + 5);
    }
    if (strncmp(command, "au_br", 5) == 0) {
        return setProperty(operations, GLOBAL_AUTO_REFRESH_PROPERTY, command + 5);
    }
    if (strncmp(command, "an_fl", 5) == 0) {
        return setProperty(operations, ANTI_FLICKER_PROPERTY, command + 5);
    }
    return MP01_COMMAND_FAILED;
}
