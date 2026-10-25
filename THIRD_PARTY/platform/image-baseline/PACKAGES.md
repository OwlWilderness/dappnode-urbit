# Exact installed APK notice mapping

Generated from `installed-notices/inventory.json` and `coverage.json`. All entries are partial notice evidence, not legal clearance or a final-image SBOM.

| Installed APK | APK license declaration | Exact Alpine recipe | Notice evidence |
| --- | --- | --- | --- |
| `alpine-release=3.24.2-r0` | MIT | [alpine-base](recipes/alpine-base-APKBUILD) [1] | **NOTICE TEXT GAP** |
| `alpine-baselayout=3.7.2-r1` | GPL-2.0-only | [alpine-baselayout](recipes/alpine-baselayout-APKBUILD) [2] | **NOTICE TEXT GAP** |
| `alpine-baselayout-data=3.7.2-r1` | GPL-2.0-only | [alpine-baselayout](recipes/alpine-baselayout-APKBUILD) [2] | **NOTICE TEXT GAP** |
| `alpine-keys=2.6-r0` | MIT | [alpine-keys](recipes/alpine-keys-APKBUILD) [3] | **NOTICE TEXT GAP** |
| `apk-tools=3.0.8-r0` | GPL-2.0-only | [apk-tools](recipes/apk-tools-APKBUILD) [4] | `notices/apk-tools--apk-tools-v3.0.8__LICENSE` |
| `libapk=3.0.8-r0` | GPL-2.0-only | [apk-tools](recipes/apk-tools-APKBUILD) [4] | `notices/apk-tools--apk-tools-v3.0.8__LICENSE` |
| `busybox=1.37.0-r31` | GPL-2.0-only | [busybox](recipes/busybox-APKBUILD) [5] | `notices/busybox--busybox-1.37.0__LICENSE`; `notices/busybox--busybox-1.37.0__archival__libarchive__bz__LICENSE`; `notices/busybox--alpine-ssl_client.c` |
| `busybox-binsh=1.37.0-r31` | GPL-2.0-only | [busybox](recipes/busybox-APKBUILD) [5] | `notices/busybox--busybox-1.37.0__LICENSE`; `notices/busybox--busybox-1.37.0__archival__libarchive__bz__LICENSE`; `notices/busybox--alpine-ssl_client.c` |
| `ssl_client=1.37.0-r31` | GPL-2.0-only | [busybox](recipes/busybox-APKBUILD) [5] | `notices/busybox--busybox-1.37.0__LICENSE`; `notices/busybox--busybox-1.37.0__archival__libarchive__bz__LICENSE`; `notices/busybox--alpine-ssl_client.c` |
| `libbz2=1.0.8-r6` | bzip2-1.0.6 | [bzip2](recipes/bzip2-APKBUILD) [6] | `notices/bzip2--bzip2-1.0.8__LICENSE` |
| `ca-certificates-bundle=20260909-r0` | MPL-2.0 AND MIT | [ca-certificates](recipes/ca-certificates-APKBUILD) [7] | **NOTICE TEXT GAP** |
| `libexpat=2.9.0-r0` | MIT | [expat](recipes/expat-APKBUILD) [8] | `notices/expat--expat-2.9.0__COPYING` |
| `libgcc=15.2.0-r5` | GPL-2.0-or-later AND LGPL-2.1-or-later | [gcc](recipes/gcc-APKBUILD) [9] | `notices/gcc--COPYING3`; `notices/gcc--COPYING.LIB`; `notices/gcc--COPYING.RUNTIME`; `notices/gcc--libstdc++-v3__doc__html__manual__license.html` |
| `libstdc++=15.2.0-r5` | GPL-2.0-or-later AND LGPL-2.1-or-later | [gcc](recipes/gcc-APKBUILD) [9] | `notices/gcc--COPYING3`; `notices/gcc--COPYING.LIB`; `notices/gcc--COPYING.RUNTIME`; `notices/gcc--libstdc++-v3__doc__html__manual__license.html` |
| `gdbm=1.26-r0` | GPL-3.0-or-later | [gdbm](recipes/gdbm-APKBUILD) [10] | `notices/gdbm--gdbm-1.26__COPYING` |
| `libffi=3.5.2-r1` | MIT | [libffi](recipes/libffi-APKBUILD) [11] | `notices/libffi--libffi-3.5.2__LICENSE`; `notices/libffi--libffi-3.5.2__LICENSE-BUILDTOOLS` |
| `mpdecimal=4.0.1-r0` | BSD-2-Clause | [mpdecimal](recipes/mpdecimal-APKBUILD) [12] | `notices/mpdecimal--mpdecimal-4.0.1__COPYRIGHT.txt`; `notices/mpdecimal--mpdecimal-4.0.1__doc__COPYRIGHT.txt` |
| `musl=1.2.6-r2` | MIT | [musl](recipes/musl-APKBUILD) [13] | `notices/musl--musl-1.2.6__COPYRIGHT`; `notices/musl--alpine-getconf.c`; `notices/musl--alpine-getent.c`; `notices/musl--alpine-iconv.c`; `notices/musl--alpine-ldconfig`; `notices/musl--alpine-__stack_chk_fail_local.c` |
| `musl-utils=1.2.6-r2` | MIT AND BSD-2-Clause AND GPL-2.0-or-later | [musl](recipes/musl-APKBUILD) [13] | `notices/musl--musl-1.2.6__COPYRIGHT`; `notices/musl--alpine-getconf.c`; `notices/musl--alpine-getent.c`; `notices/musl--alpine-iconv.c`; `notices/musl--alpine-ldconfig`; `notices/musl--alpine-__stack_chk_fail_local.c` |
| `libncursesw=6.6_p20260516-r0` | X11 | [ncurses](recipes/ncurses-APKBUILD) [14] | `notices/ncurses--COPYING` |
| `libpanelw=6.6_p20260516-r0` | X11 | [ncurses](recipes/ncurses-APKBUILD) [14] | `notices/ncurses--COPYING` |
| `ncurses-terminfo-base=6.6_p20260516-r0` | X11 | [ncurses](recipes/ncurses-APKBUILD) [14] | `notices/ncurses--COPYING` |
| `nginx=1.30.6-r0` | BSD-2-Clause | [nginx](recipes/nginx-APKBUILD) [15] | `../licenses/nginx-LICENSE.txt` |
| `libcrypto3=3.5.9-r0` | Apache-2.0 | [openssl](recipes/openssl-APKBUILD) [16] | `../licenses/openssl-LICENSE.txt` |
| `libssl3=3.5.9-r0` | Apache-2.0 | [openssl](recipes/openssl-APKBUILD) [16] | `../licenses/openssl-LICENSE.txt` |
| `openssl=3.5.9-r0` | Apache-2.0 | [openssl](recipes/openssl-APKBUILD) [16] | `../licenses/openssl-LICENSE.txt` |
| `scanelf=1.3.9-r1` | GPL-2.0-only | [pax-utils](recipes/pax-utils-APKBUILD) [17] | `notices/pax-utils--pax-utils-1.3.9__COPYING` |
| `pcre2=10.49-r0` | BSD-3-Clause | [pcre2](recipes/pcre2-APKBUILD) [18] | `notices/pcre2--pcre2-10.49__COPYING`; `notices/pcre2--pcre2-10.49__deps__sljit__LICENSE`; `notices/pcre2--pcre2-10.49__cmake__COPYING-CMAKE-SCRIPTS` |
| `pyc=3.14.8-r0` | PSF-2.0 | [python3](recipes/python3-APKBUILD) [19] | `../licenses/python3-LICENSE.txt`; `installed-notices/notice-b0e25a78cffb43f4d92de8b61ccfa1f1f98ecbc22330b54b5251e7b6ba010231.txt` |
| `python3=3.14.8-r0` | PSF-2.0 | [python3](recipes/python3-APKBUILD) [19] | `../licenses/python3-LICENSE.txt`; `installed-notices/notice-b0e25a78cffb43f4d92de8b61ccfa1f1f98ecbc22330b54b5251e7b6ba010231.txt` |
| `python3-pyc=3.14.8-r0` | PSF-2.0 | [python3](recipes/python3-APKBUILD) [19] | `../licenses/python3-LICENSE.txt`; `installed-notices/notice-b0e25a78cffb43f4d92de8b61ccfa1f1f98ecbc22330b54b5251e7b6ba010231.txt` |
| `python3-pycache-pyc0=3.14.8-r0` | PSF-2.0 | [python3](recipes/python3-APKBUILD) [19] | `../licenses/python3-LICENSE.txt`; `installed-notices/notice-b0e25a78cffb43f4d92de8b61ccfa1f1f98ecbc22330b54b5251e7b6ba010231.txt` |
| `readline=8.3.3-r1` | GPL-3.0-or-later | [readline](recipes/readline-APKBUILD) [20] | `notices/readline--readline-8.3__COPYING` |
| `sqlite-libs=3.53.4-r0` | blessing | [sqlite](recipes/sqlite-APKBUILD) [21] | `notices/sqlite--sqlite-autoconf-3530400__autosetup__LICENSE`; `notices/sqlite--sqlite-autoconf-3530400__tea__license.terms` |
| `xz-libs=5.8.4-r0` | GPL-2.0-or-later AND 0BSD AND Public-Domain AND LGPL-2.1-or-later | [xz](recipes/xz-APKBUILD) [22] | `notices/xz--xz-5.8.4__COPYING`; `notices/xz--xz-5.8.4__COPYING.0BSD`; `notices/xz--xz-5.8.4__COPYING.GPLv2`; `notices/xz--xz-5.8.4__COPYING.GPLv3`; `notices/xz--xz-5.8.4__COPYING.LGPLv2.1`; `notices/xz--xz-5.8.4__build-aux__license-check.sh` |
| `zlib=1.3.2-r1` | Zlib | [zlib](recipes/zlib-APKBUILD) [23] | `../licenses/zlib-LICENSE.txt` |

## Recipe sources

[1] https://raw.githubusercontent.com/alpinelinux/aports/d9d560d5de74ff9a7a73f3c903d6f126a0bf3142/main/alpine-base/APKBUILD
[2] https://raw.githubusercontent.com/alpinelinux/aports/60a7585bbab2fa0f762504eb617dbca90216e31f/main/alpine-baselayout/APKBUILD
[3] https://raw.githubusercontent.com/alpinelinux/aports/b9f23becced4d7b3ccc0fa0f28530243ccd314a0/main/alpine-keys/APKBUILD
[4] https://raw.githubusercontent.com/alpinelinux/aports/4588b452722bd4800efdc6cce4f6e980e02a997f/main/apk-tools/APKBUILD
[5] https://raw.githubusercontent.com/alpinelinux/aports/c3ef5d10e6ef6528852c51f0564963e2f8c1be19/main/busybox/APKBUILD
[6] https://raw.githubusercontent.com/alpinelinux/aports/33283848034c9885d984c8e8697c645c57324938/main/bzip2/APKBUILD
[7] https://raw.githubusercontent.com/alpinelinux/aports/eb7078df3a16d666e8f7723f94bb92e00d4b9236/main/ca-certificates/APKBUILD
[8] https://raw.githubusercontent.com/alpinelinux/aports/c10df79ce35862cf273f98f6eb78d52e4f064ac7/main/expat/APKBUILD
[9] https://raw.githubusercontent.com/alpinelinux/aports/423a8ad043d07f2c7546c8ec3e2b0384cda360ae/main/gcc/APKBUILD
[10] https://raw.githubusercontent.com/alpinelinux/aports/1ea03990396db618edfcc8a9a0bc6b72662bac8f/main/gdbm/APKBUILD
[11] https://raw.githubusercontent.com/alpinelinux/aports/2c2a7bb4a8b16066834e90402567b2c19403a790/main/libffi/APKBUILD
[12] https://raw.githubusercontent.com/alpinelinux/aports/c0519b85456e9b838e3142e1d233aab0b433b476/main/mpdecimal/APKBUILD
[13] https://raw.githubusercontent.com/alpinelinux/aports/f5640d3a10f664c9119720c60515265d3d6f6d01/main/musl/APKBUILD
[14] https://raw.githubusercontent.com/alpinelinux/aports/2cee8a7328d061418336ad327b512d96bcd7bc5e/main/ncurses/APKBUILD
[15] https://raw.githubusercontent.com/alpinelinux/aports/afc9f8046186db82c3c1b41cc1b4f1125e150f39/main/nginx/APKBUILD
[16] https://raw.githubusercontent.com/alpinelinux/aports/29b9ec24b1b5b39aeef51fa2a044210e2ec5258e/main/openssl/APKBUILD
[17] https://raw.githubusercontent.com/alpinelinux/aports/c61801eeacb3ffcd9c2025b09e402153bb93fb39/main/pax-utils/APKBUILD
[18] https://raw.githubusercontent.com/alpinelinux/aports/3d497cbb3217749c4fb85f90f3b6f7908b0c1f95/main/pcre2/APKBUILD
[19] https://raw.githubusercontent.com/alpinelinux/aports/bc27f38b89f034547fd7da4dba62eeb6a0daeb3b/main/python3/APKBUILD
[20] https://raw.githubusercontent.com/alpinelinux/aports/a854c03acdac188901fb012f7acbee70a36e8041/main/readline/APKBUILD
[21] https://raw.githubusercontent.com/alpinelinux/aports/a9c3ba8b9129ec0f294d0a9bf538c2f1632bb016/main/sqlite/APKBUILD
[22] https://raw.githubusercontent.com/alpinelinux/aports/0c088d609f9fe69eedd6b4c7f4b99cdad847c20a/main/xz/APKBUILD
[23] https://raw.githubusercontent.com/alpinelinux/aports/0afa2da0e8c8051c6f8f64a7a388e5a259904245/main/zlib/APKBUILD
