// SPDX-License-Identifier: MIT OR Apache-2.0
//
// This file is licensed under the MIT license or the Apache License, Version 2.0, at your choice.
//
// Copyright 2016 Fedor Gogolev
// Copyright 2025 Oliver Old
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

extern crate daemonize_tests;
extern crate tempfile;

use daemonize_tests::{Tester, STDERR_DATA, STDOUT_DATA};
use tempfile::TempDir;

#[test]
fn simple() {
    let result = Tester::new().run();
    assert!(result.is_ok())
}

#[test]
fn chdir() {
    let result = Tester::new().run();
    assert_eq!(result.unwrap().cwd.as_str(), "/");

    let result = Tester::new().working_directory("/usr").run();
    assert_eq!(result.unwrap().cwd.as_str(), "/usr");
}

#[test]
fn umask() {
    let tmpdir = TempDir::new().unwrap();
    let path = tmpdir.path().join("umask-test");

    let result = Tester::new().umask(0o222).additional_file(&path).run();
    assert!(result.is_ok());
    assert!(path.metadata().unwrap().permissions().readonly());
}

#[test]
fn pid() {
    let tmpdir = TempDir::new().unwrap();
    let path = tmpdir.path().join("pid");

    let result = Tester::new()
        .pid_file(&path)
        .sleep(std::time::Duration::from_secs(5))
        .run();
    let pid_content = std::fs::read_to_string(&path).unwrap();
    assert!(pid_content.ends_with('\n'));
    let pid = pid_content[..pid_content.len() - 1].parse().unwrap();
    assert_eq!(result.unwrap().pid, pid);

    let result = Tester::new().pid_file(&path).run();
    assert!(result.is_err());
}

#[test]
fn redirect_stream() {
    let tmpdir = TempDir::new().unwrap();
    let stdout = tmpdir.path().join("stdout");
    let stderr = tmpdir.path().join("stderr");

    Tester::new().stdout(&stdout).stderr(&stderr).run().unwrap();

    assert_eq!(&std::fs::read_to_string(&stdout).unwrap(), STDOUT_DATA);
    assert_eq!(&std::fs::read_to_string(&stderr).unwrap(), STDERR_DATA);

    std::fs::remove_file(&stdout).unwrap();
    std::fs::remove_file(&stderr).unwrap();

    Tester::new().stdout(&stdout).run().unwrap();
    assert_eq!(&std::fs::read_to_string(&stdout).unwrap(), STDOUT_DATA);
    assert_eq!(
        std::fs::metadata(&stderr).unwrap_err().kind(),
        std::io::ErrorKind::NotFound
    );

    std::fs::remove_file(&stdout).unwrap();

    Tester::new().stderr(&stderr).run().unwrap();
    assert_eq!(
        std::fs::metadata(&stdout).unwrap_err().kind(),
        std::io::ErrorKind::NotFound
    );
    assert_eq!(&std::fs::read_to_string(&stderr).unwrap(), STDERR_DATA);
}
