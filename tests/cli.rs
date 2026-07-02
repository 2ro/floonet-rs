#[cfg(test)]
mod tests {
    use floonet_rs::cli::CLIArgs;

    #[test]
    fn cli_tests() {
        use clap::CommandFactory;
        CLIArgs::command().debug_assert();
    }
}
