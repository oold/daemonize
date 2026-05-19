FROM mcr.microsoft.com/devcontainers/rust:latest@sha256:e0511e459bc13c6e54cee5a18709ba9d772ff68c996fceacb81381f9acc67fb8

# ACL shenanigans are breaking the umask test. Create an unaffected directory.
ENV DAEMONIZE_UMASK_TEST_DIR=/daemonize_umask_test

# We need this user and group for setuid/setgid tests.
RUN useradd daemonize-test
