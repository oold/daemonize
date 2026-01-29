FROM mcr.microsoft.com/devcontainers/rust:latest@sha256:a2c6743c07f80824a2f76cb591665779e064f36661142e93232a9ffe892e7a9c

# ACL shenanigans are breaking the umask test. Create an unaffected directory.
ENV DAEMONIZE_UMASK_TEST_DIR=/daemonize_umask_test

# We need this user and group for setuid/setgid tests.
RUN useradd daemonize-test
