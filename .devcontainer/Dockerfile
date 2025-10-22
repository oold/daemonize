FROM mcr.microsoft.com/devcontainers/rust:latest@sha256:63231d1d4293573ace51ae403cc6c4a2b04e332e668cd4aa132b563496b99ebd

# ACL shenanigans are breaking the umask test. Create an unaffected directory.
ENV DAEMONIZE_UMASK_TEST_DIR=/daemonize_umask_test

# We need this user and group for setuid/setgid tests.
RUN useradd daemonize-test
