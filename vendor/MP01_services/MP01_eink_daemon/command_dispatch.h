#ifndef MP01_COMMAND_DISPATCH_H
#define MP01_COMMAND_DISPATCH_H

typedef enum {
    MP01_COMMAND_FAILED,
    MP01_COMMAND_APPLIED,
    /* init accepted a property; its later debugfs write is not confirmed. */
    MP01_COMMAND_ACCEPTED,
} Mp01CommandResult;

typedef struct {
    int (*write_node)(const char* path, const char* value, void* context);
    int (*set_property)(const char* name, const char* value, void* context);
    void* context;
} Mp01CommandOperations;

Mp01CommandResult mp01DispatchCommand(
        const char* command, const Mp01CommandOperations* operations);

#endif
