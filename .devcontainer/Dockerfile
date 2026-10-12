FROM mcr.microsoft.com/devcontainers/rust:latest@sha256:269f7cd057eaccb52c17e9461f42ac5cc1bff564b0723be49ea91726f5753bb7

# ACL shenanigans are breaking the umask test. Create an unaffected directory.
ENV DAEMONIZE_UMASK_TEST_DIR=/daemonize_umask_test

# We need this user and group for setuid/setgid tests.
RUN useradd daemonize-test
