FROM mcr.microsoft.com/devcontainers/rust:latest@sha256:1707e2a8007968925f110c0961811200e9bb10e0ec055e2734857c59189a8b13

# ACL shenanigans are breaking the umask test. Create an unaffected directory.
ENV DAEMONIZE_UMASK_TEST_DIR=/daemonize_umask_test

# We need this user and group for setuid/setgid tests.
RUN useradd daemonize-test
