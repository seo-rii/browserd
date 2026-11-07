use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let helper_args = std::env::args_os().skip(1).collect::<Vec<_>>();
    if helper_args.len() == 2
        && (helper_args[0] == "--internal-worker" || helper_args[0] == "--internal-namespace")
    {
        let input = PathBuf::from(&helper_args[1]);
        if !input.is_absolute() {
            return ExitCode::from(2);
        }
        let kind = if helper_args[0] == "--internal-worker" {
            "worker"
        } else {
            "namespace"
        };
        return match browser_worker::kernel_probe::run_probe_helper(kind, &input) {
            Ok(()) => ExitCode::SUCCESS,
            Err(message) => {
                eprintln!("private probe helper refused: {message}");
                ExitCode::from(2)
            }
        };
    }
    let mut args = std::env::args_os().skip(1);
    let parsed = (|| {
        let preflight = match args.next()?.to_str()? {
            "--request" => false,
            "--preflight-request" => true,
            _ => return None,
        };
        let request = PathBuf::from(args.next()?);
        if args.next()? != "--response" {
            return None;
        }
        let response = PathBuf::from(args.next()?);
        if args.next().is_some() || !request.is_absolute() || !response.is_absolute() {
            return None;
        }
        Some((request, response, preflight))
    })();
    let Some((request, response, preflight)) = parsed else {
        eprintln!(
            "usage: browserd-kernel-probe (--request|--preflight-request) ABS_REQUEST --response ABS_RESPONSE"
        );
        return ExitCode::from(2);
    };
    let result = if preflight {
        browser_worker::kernel_probe::run_kernel_preflight(&request, &response)
    } else {
        browser_worker::kernel_probe::run_kernel_probe(&request, &response)
    };
    match result {
        Ok(code) => ExitCode::from(code),
        Err(message) => {
            eprintln!("kernel probe refused: {message}");
            ExitCode::from(2)
        }
    }
}
