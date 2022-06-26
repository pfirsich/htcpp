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
COPY meson.build /build/
COPY subprojects /build/subprojects/
RUN meson setup build/
RUN meson configure \
  -Dbuildtype=release \
  -Db_lto=true \
  -Dclipp:default_library=static \
  -Dliburingpp:default_library=static \
  build/
RUN meson compile -C build/

FROM ubuntu:22.04 AS runtime
COPY --from=builder /build/build/htcpp /usr/local/bin/
ENTRYPOINT ["htcpp"]
