FROM mcr.microsoft.com/devcontainers/rust:latest@sha256:2bf8d694491c0cd5edb860bd984f45b50a0207df75fdc707c378cf7c1ac83620

# ACL shenanigans are breaking the umask test. Create an unaffected directory.
ENV DAEMONIZE_UMASK_TEST_DIR=/daemonize_umask_test

# We need this user and group for setuid/setgid tests.
RUN useradd daemonize-test
