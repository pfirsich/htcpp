FROM ubuntu:22.04 as builder

RUN apt-get update && apt-get install --yes \
  clang \
  libssl-dev \
  meson \
  ninja-build \
  pkg-config \
  && true
WORKDIR /build/
COPY src /build/src/
COPY meson.build meson_options.txt /build/
COPY subprojects /build/subprojects/
RUN meson setup -Dbuild_libexample=false -Dbuild_unittests=false build/
RUN meson configure \
  -Dbuildtype=release \
  -Db_lto=true \
  -Dclipp:default_library=static \
  -Dcpprom:default_library=static \
  -Djoml-cpp:default_library=static \
  -Dliburingpp:default_library=static \
  build/
RUN meson compile -C build/

FROM ubuntu:22.04 AS runtime
COPY --from=builder /build/build/htcpp /usr/local/bin/
ENTRYPOINT ["htcpp"]
