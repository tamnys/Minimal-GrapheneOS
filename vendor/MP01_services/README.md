# MP01 hardware services

These are source components for the experimental GrapheneOS-derived MP01
product. They are not a built or installation-ready image. The accessibility
app is built by Android's `Android.bp`; the standalone Gradle metadata is kept
for source development, while the Gradle wrapper binary and legacy raster icon
copies are omitted from this review repository. Android 17 uses the retained
adaptive icon XML under `res/mipmap-anydpi`.

Before installation, the complete signed image and device-specific recovery
path require independent validation. No source or artifact in this directory
authorizes a flash or a data wipe. A clean install requires confirmation for
that particular flashing session.

Default E-ink features Usage:

**Single Press E-Ink Button** - Refresh Screen

**Double Press E-Ink Button** - Open E-Ink Menu with settings for Per-App refresh modes.

These mappings can be easily changed in the E-Ink Settings app

Also, the default refresh mode can be changed in the e-ink settings app. The ideal mode is balanced. The other modes might make some elements invisible.

## E-ink control socket

Android init creates and listens on `/dev/socket/MP01_eink_socket` with mode
`0600` and owner `system` before starting the daemon. The daemon accepts only
the inherited socket and checks each client's UID with `SO_PEERCRED`; its
SELinux policy grants socket access to the `system_app` domain.

Device acceptance still needs to verify that an unprivileged app cannot bind
the socket path or connect to it, that a non-system UID is rejected by the
daemon, and that stopping and restarting the daemon restores the endpoint.

## Keyboard
The MP01 image installs `aw9523b-key.idc`, `aw9523b-key.kl`, and
`aw9523b-key.kcm` into `system/usr`. The system key character map matches
FinQwerty's Minimal Phone MP01 layout, so manual FinQwerty layout selection
should not be required when these files are present.

The input-device configuration selects the MP01-specific layout by name. The
framework `Generic.kl` remains unchanged so these mappings cannot affect other
keyboards.

# Licensing

## MIT License
Most of the project is licensed under the MIT License unless specified otherwise

The code and releases are provided “as is,” without any express or implied warranty of any kind including warranties of merchantability, non-infringement, title, or fitness for a particular purpose.

## Apache License 2.0
The file `HardwareGestureDetector.kt` includes code derived from AOSP. The original code is subject to the following license:

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.

Modifications and additions to the original code are licensed under the MIT License
