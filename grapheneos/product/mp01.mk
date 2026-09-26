# Experimental MP01 product. Device compatibility remains a measured gate.
$(call inherit-product, build/make/target/product/aosp_arm64.mk)
$(call inherit-product, build/make/target/product/gsi_release.mk)
$(call inherit-product, vendor/MP01_services/MP01_services.mk)

PRODUCT_NAME := mp01
PRODUCT_DEVICE := mp01
PRODUCT_BRAND := MP01OS
PRODUCT_SYSTEM_NAME := mp01
PRODUCT_SYSTEM_DEVICE := mp01
PRODUCT_SYSTEM_BRAND := MP01OS
PRODUCT_SYSTEM_MODEL := MP01
PRODUCT_SYSTEM_MANUFACTURER := Minimal
PRODUCT_MODEL := MP01
PRODUCT_MANUFACTURER := Minimal
PRODUCT_CHARACTERISTICS := device

# Keep GrapheneOS's framework, permission model, sandboxed Play compatibility,
# backup transport and upstream-presigned apps. No partner GMS product is used.
PRODUCT_PACKAGES += inkos Seedvault

# This independently signed derivative has USB updates only. The upstream
# Updater is conditional on OFFICIAL_BUILD, which the runner leaves unset.
# Auditor requires supported hardware and must not imply Pixel attestation.
# The MP01-scoped build/make patch excludes Auditor; keep that decision out of
# the generic GrapheneOS package definitions for all other products.

# No vendor or kernel SPL override: their actual properties remain vendor-owned.
# Do not set ro.build.fingerprint to impersonate an upstream supported device.
# No legacy patch directory, PHH base.mk, signature spoofing or root integration
# is inherited here. Add vendor compatibility only with device evidence.
