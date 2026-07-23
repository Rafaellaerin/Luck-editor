#![forbid(unsafe_code)]

use clap::{Args, Parser, Subcommand, ValueEnum};
use luck_core::{
    parse_cookies, serialize_cookies, CookiePolicy, CookieQuery, InputFormat, OutputFormat, ParseOptions,
    SerializeOptions, ValidationConfig,
};
use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "luck", version, about = "Strict cookie parsing and auditing for Luck Editor")]
struct Application {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Convert(ConvertArguments),
    Validate(ValidateArguments),
    Query(QueryArguments),
    Audit(AuditArguments),
}

#[derive(Debug, Args)]
struct InputArguments {
    #[arg(short, long, value_name = "FILE", help = "Read from a file instead of standard input")]
    input: Option<PathBuf>,
    #[arg(long, default_value = "", help = "Fallback domain for formats without domain attributes")]
    domain: String,
    #[arg(long, value_enum, default_value_t = CliInputFormat::Auto)]
    input_format: CliInputFormat,
    #[arg(long, default_value_t = 2 * 1024 * 1024)]
    maximum_bytes: usize,
    #[arg(long, default_value_t = 5_000)]
    maximum_cookies: usize,
    #[arg(long, help = "Keep invalid cookies instead of rejecting them")]
    keep_invalid: bool,
}

#[derive(Debug, Args)]
struct ConvertArguments {
    #[command(flatten)]
    input: InputArguments,
    #[arg(short, long, value_name = "FILE", help = "Write to a file instead of standard output")]
    output: Option<PathBuf>,
    #[arg(long, value_enum, default_value_t = CliOutputFormat::RedactedJson)]
    output_format: CliOutputFormat,
    #[arg(long, help = "Include HttpOnly cookies in output")]
    include_http_only: bool,
    #[arg(long, help = "Emit compact JSON")]
    compact: bool,
}

#[derive(Debug, Args)]
struct ValidateArguments {
    #[command(flatten)]
    input: InputArguments,
    #[arg(long, help = "Return failure when warnings are present")]
    deny_warnings: bool,
}

#[derive(Debug, Args)]
struct QueryArguments {
    #[command(flatten)]
    input: InputArguments,
    #[arg(value_name = "QUERY", help = "Query such as 'domain:example.com and secure:true'")]
    query: String,
    #[arg(long, value_enum, default_value_t = CliOutputFormat::RedactedJson)]
    output_format: CliOutputFormat,
    #[arg(long)]
    include_http_only: bool,
}

#[derive(Debug, Args)]
struct AuditArguments {
    #[command(flatten)]
    input: InputArguments,
    #[arg(long, help = "Require Secure on every cookie")]
    require_secure: bool,
    #[arg(long, value_delimiter = ',', help = "Comma-separated domain allowlist")]
    allow_domain: Vec<String>,
    #[arg(long, value_delimiter = ',', help = "Comma-separated denied domain suffixes")]
    deny_domain: Vec<String>,
    #[arg(long, default_value_t = 400)]
    maximum_lifetime_days: u64,
    #[arg(long, help = "Write machine-readable JSON")]
    json: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliInputFormat {
    Auto,
    Json,
    Netscape,
    Header,
    SetCookie,
    Lines,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliOutputFormat {
    Json,
    RedactedJson,
    Netscape,
    Header,
    SetCookie,
    Curl,
}

fn main() {
    if let Err(error) = run(Application::parse()) {
        eprintln!("luck: {error}");
        std::process::exit(1);
    }
}

fn run(application: Application) -> luck_core::Result<()> {
    match application.command {
        Command::Convert(arguments) => convert(arguments),
        Command::Validate(arguments) => validate(arguments),
        Command::Query(arguments) => query(arguments),
        Command::Audit(arguments) => audit(arguments),
    }
}

fn convert(arguments: ConvertArguments) -> luck_core::Result<()> {
    let report = load(&arguments.input)?;
    for warning in &report.warnings {
        eprintln!("warning: {}{}", warning.message, warning.line.map(|line| format!(" (line {line})")).unwrap_or_default());
    }
    let output = serialize_cookies(
        &report.cookies,
        &SerializeOptions {
            format: arguments.output_format.into(),
            hostname: arguments.input.domain.clone(),
            include_http_only: arguments.include_http_only,
            pretty_json: !arguments.compact,
            include_metadata: false,
        },
    )?;
    write_output(arguments.output.as_ref(), &output)
}

fn validate(arguments: ValidateArguments) -> luck_core::Result<()> {
    let report = load(&arguments.input)?;
    println!("format: {:?}", report.format);
    println!("accepted: {}", report.cookies.len());
    println!("rejected: {}", report.rejected);
    println!("duplicates removed: {}", report.duplicates_removed);
    println!("warnings: {}", report.warnings.len());
    for warning in &report.warnings {
        println!("- {}: {}", warning.code, warning.message);
    }
    if report.rejected > 0 || (arguments.deny_warnings && !report.warnings.is_empty()) {
        return Err(luck_core::LuckError::Validation("input did not satisfy validation requirements".into()));
    }
    Ok(())
}

fn query(arguments: QueryArguments) -> luck_core::Result<()> {
    let report = load(&arguments.input)?;
    let query = CookieQuery::parse(&arguments.query)?;
    let result = query.execute(&report.cookies);
    let output = serialize_cookies(
        &result,
        &SerializeOptions {
            format: arguments.output_format.into(),
            hostname: arguments.input.domain,
            include_http_only: arguments.include_http_only,
            ..SerializeOptions::default()
        },
    )?;
    print!("{output}");
    Ok(())
}

fn audit(arguments: AuditArguments) -> luck_core::Result<()> {
    let report = load(&arguments.input)?;
    let policy = CookiePolicy {
        require_secure: arguments.require_secure,
        allow_domains: arguments.allow_domain,
        deny_domain_suffixes: arguments.deny_domain,
        maximum_lifetime_days: Some(arguments.maximum_lifetime_days),
        ..CookiePolicy::default()
    };
    let entries: Vec<_> = report
        .cookies
        .iter()
        .map(|cookie| serde_json::json!({
            "key": cookie.key(),
            "decision": policy.evaluate(cookie),
        }))
        .collect();
    let denied = entries.iter().filter(|entry| entry["decision"].get("Deny").is_some()).count();
    if arguments.json {
        println!("{}", serde_json::to_string_pretty(&entries)?);
    } else {
        println!("cookies: {}", entries.len());
        println!("denied: {denied}");
        for entry in &entries {
            println!("{}", serde_json::to_string(entry)?);
        }
    }
    if denied > 0 {
        return Err(luck_core::LuckError::Validation(format!("policy denied {denied} cookies")));
    }
    Ok(())
}

fn load(arguments: &InputArguments) -> luck_core::Result<luck_core::ParseReport> {
    let input = read_input(arguments.input.as_ref())?;
    parse_cookies(
        &input,
        &ParseOptions {
            format: arguments.input_format.into(),
            fallback_domain: arguments.domain.clone(),
            maximum_input_bytes: arguments.maximum_bytes,
            maximum_cookies: arguments.maximum_cookies,
            reject_invalid: !arguments.keep_invalid,
            deduplicate: true,
            validation: ValidationConfig::default(),
        },
    )
}

fn read_input(path: Option<&PathBuf>) -> io::Result<String> {
    match path {
        Some(path) => fs::read_to_string(path),
        None => {
            let mut input = String::new();
            io::stdin().read_to_string(&mut input)?;
            Ok(input)
        }
    }
}

fn write_output(path: Option<&PathBuf>, output: &str) -> luck_core::Result<()> {
    match path {
        Some(path) => fs::write(path, output)?,
        None => io::stdout().write_all(output.as_bytes())?,
    }
    Ok(())
}

impl From<CliInputFormat> for InputFormat {
    fn from(value: CliInputFormat) -> Self {
        match value {
            CliInputFormat::Auto => Self::Auto,
            CliInputFormat::Json => Self::Json,
            CliInputFormat::Netscape => Self::Netscape,
            CliInputFormat::Header => Self::CookieHeader,
            CliInputFormat::SetCookie => Self::SetCookie,
            CliInputFormat::Lines => Self::Lines,
        }
    }
}

impl From<CliOutputFormat> for OutputFormat {
    fn from(value: CliOutputFormat) -> Self {
        match value {
            CliOutputFormat::Json => Self::Json,
            CliOutputFormat::RedactedJson => Self::RedactedJson,
            CliOutputFormat::Netscape => Self::Netscape,
            CliOutputFormat::Header => Self::CookieHeader,
            CliOutputFormat::SetCookie => Self::SetCookie,
            CliOutputFormat::Curl => Self::Curl,
        }
    }
}
