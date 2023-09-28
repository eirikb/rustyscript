# js_playground

## Simple deno wrapper for module execution

This crate is meant to provide a quick and simple way to integrate a runtime JS or TS component from within rust.
By default, the code being run is entirely sandboxed from the host, having no filesystem or network access.

Typescript is supported by default

It can be extended to include the capabilities and more if desired - please see the `runtime_extensions` example

Asynchronous code is supported - I suggest using the timeout option when creating your runtime to avoid infinite hangs:
```rust
use js_playground::{Runtime, RuntimeOptions};
use std::time::Duration;

let runtime = Runtime::new(RuntimeOptions {
    timeout: Some(Duration::from_millis(50)),
    ..Default::default()
}).expect("Something went wrong creating the runtime");
```

Here is a very basic use of this crate to execute a JS module. It will create a basic runtime, load the script,
call the registered entrypoint function with the given arguments, and return the resulting value:
```rust
use js_playground::{Runtime, Script, Error};

let script = Script::new(
    "test.js",
    "
    js_playground.register_entrypoint(
        (string, integer) => {
            console.log(`Hello world: string=${string}, integer=${integer}`);
            return 2;
        }
    )
    "
);

let value: usize = Runtime::execute_module(
    script, vec![],
    Default::default(),
    &[
        Runtime::arg("test"),
        Runtime::arg(5),
    ]
)?;

assert_eq!(value, 2);
```

If all you need is the result of a single javascript expression, you can use:
```rust
let result: i64 = js_playground::evaluate("5 + 5").expect("The expression was invalid!");
```

Scripts can also be loaded from the filesystem with `Script::load` or `Script::load_dir` if you want to collect all modules in a given directory.

A more detailed version of the crate's usage can be seen below, which breaks down the steps instead of using the one-liner `Runtime::execute_module`:
```rust
use js_playground::{Runtime, RuntimeOptions, Script, Error, Undefined};
use std::time::Duration;

let script = Script::new(
    "test.js",
    "
    let internalValue = 0;
    export const load = (value) => internalValue = value;
    export const getValue = () => internalValue;
    "
);

// Create a new runtime
let mut runtime = Runtime::new(RuntimeOptions {
    timeout: Some(Duration::from_millis(50)), // Stop execution by force after 50ms
    default_entrypoint: Some("load".to_string()), // Run this as the entrypoint function if none is registered
    ..Default::default()
})?;

// The handle returned is used to get exported functions and values from that module.
// We then call the entrypoint function, but do not need a return value.
let module_handle = runtime.load_modules(script, vec![])?;
runtime.call_entrypoint::<Undefined>(&module_handle, &[ Runtime::arg(2) ])?;

let internal_value: i64 = runtime.call_function(&module_handle, "getValue", Runtime::EMPTY_ARGS)?;
```

Please also check out [@Bromeon/js_sandbox](https://github.com/Bromeon/js-sandbox), another great crate in this niche

[![Crates.io](https://img.shields.io/crates/v/js-playground.svg)](https://crates.io/crates/js-playground)
[![Build Status](https://github.com/rscarson/js-playground/workflows/Rust/badge.svg)](https://github.com/rscarson/js-playground/actions?workflow=Rust)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://raw.githubusercontent.com/rscarson/js-playground/master/LICENSE)

