//! Explicit safety bootstrap restricted to a fresh, isolated kernel measurement.
use std::time::Duration;

use browserd_coordination::{
    RedisSafetyAuthority, RedisSafetyAuthorityConfig, SafetyActorIdentity, SafetyAuthority,
    SafetyAuthorityConfig, SafetyInitializeRequest,
};
use browserd_core::TenantId;
use uuid::Uuid;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn arguments(args: impl IntoIterator<Item = String>) -> Result<(String, String, Uuid)> {
    let args = args.into_iter().collect::<Vec<_>>();
    if !(args.len() == 6
        && args[0] == "--redis-url"
        && args[2] == "--redis-prefix"
        && args[4] == "--reason"
        && args[5] == "isolated kernel measurement")
    {
        return Err("expected an explicit isolated kernel measurement request".into());
    }
    if args[1] != "redis://127.0.0.1:16379/0" {
        return Err("initializer is restricted to the isolated container Redis endpoint".into());
    }
    let id = args[3]
        .strip_prefix("browserd-kernel-lab-")
        .ok_or("initializer requires a dedicated kernel lab prefix")?;
    let run = Uuid::parse_str(id)?;
    if run.is_nil() || run.to_string() != id {
        return Err("invalid lab run UUID".into());
    }
    Ok((args[1].clone(), args[3].clone(), run))
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let (endpoint, prefix, run) = arguments(std::env::args().skip(1))?;
    let authority = RedisSafetyAuthority::connect(RedisSafetyAuthorityConfig::new(
        endpoint,
        prefix,
        SafetyAuthorityConfig::default(),
        1,
        Duration::from_secs(5),
    )?)
    .await?;
    let request = SafetyInitializeRequest::new(
        SafetyActorIdentity::new(
            TenantId::new(),
            "operator-approved-isolated-kernel-measurement",
        )?,
        Uuid::new_v4(),
        format!("isolated kernel measurement {run}"),
    )?;
    let receipt = authority.initialize(request).await?;
    println!("{}", serde_json::to_string(&receipt)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::arguments;

    #[test]
    fn requires_exact_isolated_endpoint_prefix_and_explicit_reason() {
        let run = uuid::Uuid::new_v4();
        let args = vec![
            "--redis-url".to_owned(),
            "redis://127.0.0.1:16379/0".to_owned(),
            "--redis-prefix".to_owned(),
            format!("browserd-kernel-lab-{run}"),
            "--reason".to_owned(),
            "isolated kernel measurement".to_owned(),
        ];
        assert!(arguments(args.clone()).is_ok());
        for (index, value) in [
            (1, "redis://127.0.0.1:6379/0"),
            (3, "browserd-production"),
            (
                3,
                "browserd-kernel-lab-00000000-0000-0000-0000-000000000000",
            ),
            (5, ""),
        ] {
            let mut changed = args.clone();
            changed[index] = value.to_owned();
            assert!(arguments(changed).is_err());
        }
        assert!(arguments(args.into_iter().take(5)).is_err());
    }
}
