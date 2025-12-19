FROM mcr.microsoft.com/devcontainers/rust:latest@sha256:282e805f934b4d965bc07eaf35677d51aaa18b46b2a6cfa666178a7e6da9c287

# ACL shenanigans are breaking the umask test. Create an unaffected directory.
ENV DAEMONIZE_UMASK_TEST_DIR=/daemonize_umask_test

# We need this user and group for setuid/setgid tests.
RUN useradd daemonize-test
