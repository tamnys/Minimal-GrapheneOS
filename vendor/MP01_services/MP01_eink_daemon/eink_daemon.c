#define _GNU_SOURCE

#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <errno.h>
#include <android/log.h>
#include <cutils/sockets.h>
#include <signal.h>
#include "command_dispatch.h"
#include "command_stream.h"
#ifdef __BIONIC__
#include <sys/system_properties.h>
#else
int __system_property_set(const char* name, const char* value);
#endif

static const char* kTAG = "MP01EinkService";
#define LOGI(...) ((void)__android_log_print(ANDROID_LOG_INFO, kTAG, __VA_ARGS__))
#define LOGE(...) ((void)__android_log_print(ANDROID_LOG_ERROR, kTAG, __VA_ARGS__))

#define SOCKET_NAME "MP01_eink_socket"
#define BUFFER_SIZE 512
#define COLD_BACKLIGHT_PATH "/sys/class/leds/lcd-backlight/brightness"
#define WARM_BACKLIGHT_PATH "/sys/class/leds/led-warmlight/brightness"
#define KEYBOARD_BACKLIGHT_PATH "/sys/class/leds/keyboard-backlight/brightness"
#define STARTUP_BACKLIGHT_BRIGHTNESS "0"
#define STARTUP_BACKLIGHT_RETRIES 20
#define STARTUP_BACKLIGHT_RETRY_US 250000
#define CLIENT_READ_TIMEOUT_SECONDS 5
#define AID_SYSTEM 1000

static int writeNodeValue(const char* filePath, const char* value, void* context) {
    (void)context;
    int fd = open(filePath, O_WRONLY);
    if (fd == -1) {
        LOGE("E-ink node unavailable at %s: %s", filePath, strerror(errno));
        return 0;
    }

    ssize_t written = write(fd, value, strlen(value));
    int writeError = errno;
    int closed = close(fd);
    int closeError = errno;
    if (written != (ssize_t)strlen(value)) {
        LOGE("E-ink node write failed at %s: %s", filePath,
                written < 0 ? strerror(writeError) : "short write");
        return 0;
    }
    if (closed != 0) {
        LOGE("E-ink node close failed at %s: %s", filePath, strerror(closeError));
        return 0;
    }
    return 1;
}

static int setControlProperty(const char* propertyName, const char* value, void* context) {
    (void)context;
    if (__system_property_set(propertyName, value) != 0) {
        LOGE("Unable to set %s control property: %s", propertyName, strerror(errno));
        return 0;
    }
    return 1;
}

int writeBacklightNodeQuietly(const char* filePath, const char* brightness) {
    int fd = open(filePath, O_WRONLY);
    if (fd == -1) {
        return 0;
    }

    if (write(fd, brightness, strlen(brightness)) == -1) {
        close(fd);
        return 0;
    }

    close(fd);
    return 1;
}

void applyStartupBacklightClamp() {
    int attempt;
    for (attempt = 0; attempt < STARTUP_BACKLIGHT_RETRIES; attempt++) {
        int coldWritten = writeBacklightNodeQuietly(COLD_BACKLIGHT_PATH, STARTUP_BACKLIGHT_BRIGHTNESS);
        int warmWritten = writeBacklightNodeQuietly(WARM_BACKLIGHT_PATH, STARTUP_BACKLIGHT_BRIGHTNESS);
        int keyboardWritten = writeBacklightNodeQuietly(KEYBOARD_BACKLIGHT_PATH, STARTUP_BACKLIGHT_BRIGHTNESS);

        if (coldWritten && warmWritten && keyboardWritten) {
            LOGI("Applied startup backlight clamp");
            return;
        }

        usleep(STARTUP_BACKLIGHT_RETRY_US);
    }

    LOGE("Startup backlight clamp could not write all backlight nodes");
}


typedef struct {
    int fd;
    int reply_failed;
} ClientContext;

static void sendReply(ClientContext* client, const char* reply) {
    size_t remaining = strlen(reply);
    while (remaining > 0 && !client->reply_failed) {
        ssize_t written = send(client->fd, reply, remaining, MSG_NOSIGNAL);
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written <= 0) {
            LOGE("E-ink command reply failed: %s", strerror(errno));
            client->reply_failed = 1;
            return;
        }
        reply += written;
        remaining -= (size_t)written;
    }
}

static void processFramedCommand(const char* command, void* context) {
    ClientContext* client = context;
    if (client->reply_failed) {
        return;
    }
    const Mp01CommandOperations operations = {
        .write_node = writeNodeValue,
        .set_property = setControlProperty,
        .context = NULL,
    };
    Mp01CommandResult result = mp01DispatchCommand(command, &operations);
    if (result == MP01_COMMAND_APPLIED) {
        sendReply(client, "OK\n");
    } else if (result == MP01_COMMAND_ACCEPTED) {
        sendReply(client, "ACCEPTED\n");
    } else {
        LOGE("E-ink command failed: %s", command);
        sendReply(client, "ERR\n");
    }
}

int isAuthorizedClient(int client_sockfd) {
    struct ucred credentials;
    socklen_t credentials_length = sizeof(credentials);

    if (getsockopt(client_sockfd, SOL_SOCKET, SO_PEERCRED, &credentials, &credentials_length) == -1) {
        LOGE("Could not read socket peer credentials: %s", strerror(errno));
        return 0;
    }

    if (credentials_length != sizeof(credentials)) {
        LOGE("Socket peer credential length mismatch: %u", credentials_length);
        return 0;
    }

    if (credentials.uid == AID_SYSTEM) {
        return 1;
    }

    LOGE("Rejecting unauthorized socket peer uid=%d gid=%d pid=%d",
            credentials.uid, credentials.gid, credentials.pid);
    return 0;
}

static int configureClientTimeout(int client_sockfd) {
    const struct timeval timeout = {
        .tv_sec = CLIENT_READ_TIMEOUT_SECONDS,
        .tv_usec = 0,
    };

    if (setsockopt(client_sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == -1) {
        LOGE("Could not set client read timeout: %s", strerror(errno));
        return 0;
    }

    if (setsockopt(client_sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == -1) {
        LOGE("Could not set client write timeout: %s", strerror(errno));
        return 0;
    }

    return 1;
}

_Noreturn void setupServer() {
    int server_sockfd, client_sockfd;
    char buffer[BUFFER_SIZE];

    // init owns, binds and listens on /dev/socket/MP01_eink_socket before
    // starting this service. Never fall back to a daemon-created socket.
    server_sockfd = android_get_control_socket(SOCKET_NAME);
    if (server_sockfd < 0) {
        LOGE("Missing init-owned E-ink control socket");
        exit(EXIT_FAILURE);
    }

    LOGI("Server started listening.");

    while (1) {
        Mp01CommandStream commandStream;
        ClientContext client;
        client_sockfd = accept(server_sockfd, NULL, NULL);
        if (client_sockfd < 0) {
            LOGE("Socket accept failed: %s", strerror(errno));
            continue;
        }

        if (!isAuthorizedClient(client_sockfd)) {
            close(client_sockfd);
            continue;
        }

        if (!configureClientTimeout(client_sockfd)) {
            close(client_sockfd);
            continue;
        }

        mp01CommandStreamInit(&commandStream);
        client.fd = client_sockfd;
        client.reply_failed = 0;

        while (1) {
            ssize_t num_read = read(client_sockfd, buffer, BUFFER_SIZE);
            if (num_read > 0) {
                size_t droppedCommands = mp01CommandStreamConsume(
                        &commandStream,
                        buffer,
                        (size_t)num_read,
                        processFramedCommand,
                        &client);
                if (droppedCommands > 0) {
                    LOGE("Dropped %zu overlong command frame(s)", droppedCommands);
                }
                if (client.reply_failed) {
                    break;
                }
            } else if (num_read == 0) {
                mp01CommandStreamFinish(&commandStream, processFramedCommand, &client);
                LOGI("Client disconnected");
                break;
            } else if (errno == EINTR) {
                continue;
            } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                mp01CommandStreamDiscard(&commandStream);
                LOGI("Client read timed out; discarded incomplete command frame");
                break;
            } else {
                LOGE("Socket read failed: %s", strerror(errno));
                break;
            }
        }

        close(client_sockfd);
    }

    close(server_sockfd);
}

int main(void) {
    signal(SIGHUP, SIG_IGN);
    applyStartupBacklightClamp();
    setupServer();
    return 0;
}
