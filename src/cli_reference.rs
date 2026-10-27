//! Offline public CLI discovery, reflected from the same tree used for parsing.

use clap::{Arg, Command, CommandFactory};
use serde_json::{json, Value};

const LIMITS: &str = "Reference only: no configuration, credentials, backend, tools or network are read. Help is not a dry run: --help bypasses required/conflicting argument checks. Descriptions include conditional and runtime requirements; the schema is not a complete validator or authorization to execute. Keep private state and wallet backups. A failed or cancelled operation may already have effects; inspect its saved receipts before retrying.";

pub fn data(schema: bool) -> Value {
    let mut command = super::Cli::command().bin_name("zdn");
    command.build();
    let mut commands = Vec::new();
    collect(&mut command, &[], &[], &mut commands);
    if schema {
        json!({
            "apiVersion": "zdn-command-reference/v1alpha1",
            "version": env!("CARGO_PKG_VERSION"),
            "validationComplete": false,
            "limits": LIMITS,
            "constraintCoverage": "Required flags, explicit defaults, possible values and conflicts are reflected. Conditional requirements, numeric ranges, dynamic defaults and operational safety rules are described in help/longHelp; clap does not expose every conditional rule through its public reflection API.",
            "commands": commands,
        })
    } else {
        let mut text = format!("ZDN {} — full public command reference\n\n{LIMITS}\n\nRead ancestor options before a leaf. Non-global parent options go before its child command; global options also work below their owner.\n\n", env!("CARGO_PKG_VERSION"));
        for command in commands {
            let path: Vec<_> = command["path"]
                .as_array()
                .unwrap()
                .iter()
                .map(|part| part.as_str().unwrap())
                .collect();
            text.push_str(&format!("=== {} ===\n\n", path.join(" ")));
            text.push_str(command["longHelp"].as_str().unwrap());
            text.push_str("\n\n");
        }
        json!({"text": text})
    }
}

fn collect(command: &mut Command, parent: &[String], ancestors: &[Value], out: &mut Vec<Value>) {
    let mut path = parent.to_vec();
    path.push(command.get_name().to_owned());
    let arguments: Vec<_> = command
        .get_arguments()
        .filter(|arg| !arg.is_hide_set())
        .map(|arg| argument(command, arg))
        .collect();
    // Ask the parser for --help so clap uses the same short/long fallback and
    // formatting as the executable, including commands without long-only help.
    let help = command
        .clone()
        .try_get_matches_from([command.get_name(), "--help"])
        .unwrap_err()
        .to_string();
    out.push(json!({
        "path": path,
        "about": command.get_long_about().or(command.get_about()).map(ToString::to_string),
        "longHelp": help,
        "subcommandRequired": command.is_subcommand_required_set(),
        "arguments": arguments,
        "ancestorOptions": ancestors,
        "subcommands": command.get_subcommands().filter(|child| public(child))
            .map(|child| child.get_name()).collect::<Vec<_>>(),
    }));
    let mut ancestors = ancestors.to_vec();
    for argument in &arguments {
        if argument["position"].is_null()
            && argument["global"] == false
            && argument["id"] != "help"
            && argument["id"] != "version"
        {
            ancestors.push(json!({"path": path, "argument": argument}));
        }
    }
    for child in command.get_subcommands_mut().filter(|child| public(child)) {
        collect(child, &path, &ancestors, out);
    }
}

fn public(command: &Command) -> bool {
    !command.is_hide_set() && command.get_name() != "help"
}

fn argument(command: &Command, arg: &Arg) -> Value {
    let values = arg.get_num_args();
    json!({
        "id": arg.get_id().as_str(),
        "long": arg.get_long(),
        "short": arg.get_short().map(|value| value.to_string()),
        "aliases": arg.get_visible_aliases().unwrap_or_default(),
        "position": arg.get_index(),
        "valueNames": arg.get_value_names().map(|names| names.iter().map(|name| name.as_str()).collect::<Vec<_>>()).unwrap_or_default(),
        "takesValues": arg.get_action().takes_values(),
        "minValues": values.map(|values| values.min_values()),
        "maxValues": values.and_then(|values| (values.max_values() != usize::MAX).then(|| values.max_values())),
        "required": arg.is_required_set(),
        "global": arg.is_global_set(),
        "last": arg.is_last_set(),
        "repeatable": matches!(arg.get_action(), clap::ArgAction::Append | clap::ArgAction::Count),
        "defaults": arg.get_default_values().iter().map(|value| value.to_string_lossy()).collect::<Vec<_>>(),
        "possibleValues": arg.get_possible_values().into_iter().filter(|value| !value.is_hide_set())
            .map(|value| json!({"name": value.get_name(), "help": value.get_help().map(ToString::to_string)})).collect::<Vec<_>>(),
        "conflictsWith": command.get_arg_conflicts_with(arg).iter().filter(|other| !other.is_hide_set())
            .map(|other| other.get_id().as_str()).collect::<Vec<_>>(),
        "help": arg.get_long_help().or(arg.get_help()).map(ToString::to_string),
    })
}
