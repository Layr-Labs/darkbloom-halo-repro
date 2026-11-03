FROM docker.io/library/debian:trixie
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends erofs-utils cryptsetup-bin busybox-static \
      kmod cpio gzip xz-utils zstd systemd-ukify systemd-boot-efi python3-pefile python3-zstandard \
 && apt-get clean && rm -rf /var/lib/apt/lists/*
