FROM mcr.microsoft.com/devcontainers/rust:latest@sha256:fb71ea387adcb6452f37854dfa47d8585bc12a2f6d513da261019b47764da6b0

# ACL shenanigans are breaking the umask test. Create an unaffected directory.
ENV DAEMONIZE_UMASK_TEST_DIR=/daemonize_umask_test

# We need this user and group for setuid/setgid tests.
RUN useradd daemonize-test
