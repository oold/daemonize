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

fn main() {
    #[cfg(unix)]
    unix::main();
}

#[cfg(unix)]
mod unix {
    extern crate daemonize2;

    use std::fs::File;

    use self::daemonize2::Daemonize;

    pub fn main() {
        let stdout = File::create("/tmp/daemon.out").unwrap();
        let stderr = File::create("/tmp/daemon.err").unwrap();

        // Every method except `new` and `start` is optional. See `Daemonize` documentation for
        // default behaviour.
        let mut daemonize = Daemonize::new();

        daemonize = daemonize
            .pid_file("/tmp/test.pid")
            .chown_pid_file_user("nobody")
            .chown_pid_file_group("daemon")
            .working_directory("/tmp");

        // User and group IDs can be either strings or integers.
        daemonize = daemonize.user("nobody").group("daemon").group(2);

        // Set umask. `0o027` by default.
        daemonize = daemonize.umask(0o777);

        // Redirect standard output and standard error.
        daemonize = daemonize.stdout(stdout).stderr(stderr);

        // Run a final privileged action.
        let daemonize = daemonize.privileged_action(|| "Executed before drop privileges");

        // Start the daemon.
        match unsafe { daemonize.start() } {
            Ok(_) => println!("Success, daemonized"),
            Err(e) => eprintln!("Error, {}", e),
        }
    }
}
