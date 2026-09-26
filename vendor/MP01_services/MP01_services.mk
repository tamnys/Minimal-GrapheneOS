PRODUCT_PACKAGES += \
    MP01_eink_server \
    MP01AccessibilityService

PRODUCT_COPY_FILES += \
    vendor/MP01_services/mp_keyboard/aw9523b-key.idc:system/usr/idc/aw9523b-key.idc \
    vendor/MP01_services/mp_keyboard/aw9523b-key.kl:system/usr/keylayout/aw9523b-key.kl \
    vendor/MP01_services/mp_keyboard/aw9523b-key.kcm:system/usr/keychars/aw9523b-key.kcm

SYSTEM_EXT_PRIVATE_SEPOLICY_DIRS += \
    vendor/MP01_services/sepolicy/private
