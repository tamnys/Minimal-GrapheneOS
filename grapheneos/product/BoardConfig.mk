# Retain the installed kernel/vendor; never build replacement firmware here.
include build/make/target/board/generic_arm64/BoardConfig.mk
GSI_FILE_SYSTEM_TYPE := ext4
TARGET_NO_KERNEL := true
TARGET_NO_BOOTLOADER := true
