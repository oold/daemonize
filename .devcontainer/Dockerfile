FROM mcr.microsoft.com/devcontainers/rust:latest@sha256:1435dfe4083cddbb68e909b7ea6b370b2aa43e01a17f780e3410b422dfd93507

# ACL shenanigans are breaking the umask test. Create an unaffected directory.
ENV DAEMONIZE_UMASK_TEST_DIR=/daemonize_umask_test

# We need this user and group for setuid/setgid tests.
RUN useradd daemonize-test
