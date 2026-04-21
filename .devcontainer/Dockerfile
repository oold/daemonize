FROM mcr.microsoft.com/devcontainers/rust:latest@sha256:354a0f58f13d93fb6f24e694124fd2d24e6e5306102c7bb3bb1cb26fa4951d46

# ACL shenanigans are breaking the umask test. Create an unaffected directory.
ENV DAEMONIZE_UMASK_TEST_DIR=/daemonize_umask_test

# We need this user and group for setuid/setgid tests.
RUN useradd daemonize-test
