FROM mcr.microsoft.com/devcontainers/rust:latest@sha256:1648c1ac19ef6b55a001048d832956c109a5a9ad37fc6b3c82d37b6cd462bbf3

# ACL shenanigans are breaking the umask test. Create an unaffected directory.
ENV DAEMONIZE_UMASK_TEST_DIR=/daemonize_umask_test

# We need this user and group for setuid/setgid tests.
RUN useradd daemonize-test
