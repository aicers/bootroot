use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    #[command(subcommand)]
    Infra(InfraCommand),
    Init,
    Status,
    #[command(subcommand)]
    App(AppCommand),
    Verify,
}

#[derive(Subcommand, Debug)]
enum InfraCommand {
    Up,
}

#[derive(Subcommand, Debug)]
enum AppCommand {
    Add,
    Info,
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::Infra(InfraCommand::Up) => {
            println!("bootroot infra up: not yet implemented");
        }
        Command::Init => {
            println!("bootroot init: not yet implemented");
        }
        Command::Status => {
            println!("bootroot status: not yet implemented");
        }
        Command::App(AppCommand::Add) => {
            println!("bootroot app add: not yet implemented");
        }
        Command::App(AppCommand::Info) => {
            println!("bootroot app info: not yet implemented");
        }
        Command::Verify => {
            println!("bootroot verify: not yet implemented");
        }
    }
}
