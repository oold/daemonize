FROM mcr.microsoft.com/devcontainers/rust:latest@sha256:9813ab046899db62589dd40e43ce6b8fa20b3cc20407288b4dd647e95bb22526

# ACL shenanigans are breaking the umask test. Create an unaffected directory.
ENV DAEMONIZE_UMASK_TEST_DIR=/daemonize_umask_test

# We need this user and group for setuid/setgid tests.
RUN useradd daemonize-test
