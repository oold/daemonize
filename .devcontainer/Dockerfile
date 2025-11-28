FROM mcr.microsoft.com/devcontainers/rust:latest@sha256:884de394ad31255888950dc8d4a57ea0201908ea89af5ae68db6fc2ae2f562b3

# ACL shenanigans are breaking the umask test. Create an unaffected directory.
ENV DAEMONIZE_UMASK_TEST_DIR=/daemonize_umask_test

# We need this user and group for setuid/setgid tests.
RUN useradd daemonize-test
