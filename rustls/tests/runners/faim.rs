#![cfg_attr(read_buf, feature(read_buf))]
#![cfg_attr(read_buf, feature(core_io))]
#![cfg_attr(read_buf, feature(core_io_borrowed_buf))]

#[macro_use]
mod macros;

#[cfg(feature = "aws_lc_rs")]
#[path = "."]
mod tests_with_aws_lc_rs {
    provider_aws_lc_rs!();

    #[path = "../faim.rs"]
    mod tests;
}
