FROM mcr.microsoft.com/devcontainers/rust:latest@sha256:b12e288bacbb5633f9b7655ba1a2cf69dd2fecef662346f2a9754f019af82483

# ACL shenanigans are breaking the umask test. Create an unaffected directory.
ENV DAEMONIZE_UMASK_TEST_DIR=/daemonize_umask_test

# We need this user and group for setuid/setgid tests.
RUN useradd daemonize-test
