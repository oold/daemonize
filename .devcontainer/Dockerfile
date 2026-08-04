FROM mcr.microsoft.com/devcontainers/rust:latest@sha256:0ef7110175191659b975c1b89217217a093667851bde031b48f8ceab9cd1be1f

# ACL shenanigans are breaking the umask test. Create an unaffected directory.
ENV DAEMONIZE_UMASK_TEST_DIR=/daemonize_umask_test

# We need this user and group for setuid/setgid tests.
RUN useradd daemonize-test
