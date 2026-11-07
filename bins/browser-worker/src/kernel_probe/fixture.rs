use super::config::FixtureConfig;
use super::{ProbeError, ProbeResultValue};
use serde::Serialize;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

pub(super) const DOWNLOAD_BYTES: &[u8] = b"browserd-production-kernel-download\n";
const MAX_HEADER_BYTES: usize = 8192;
const MAX_OBSERVATION_BYTES: usize = 16 * 1024 * 1024;
#[derive(Clone, Serialize)]
pub(super) struct FixtureRequest {
    pub path: String,
    pub user_agent: Option<String>,
    pub accept_language: Option<String>,
}
#[derive(Default)]
struct Observations {
    requests: Vec<FixtureRequest>,
    bytes: usize,
    overflow: bool,
}
pub(super) struct Fixture {
    origin: String,
    prefix: String,
    requests: Arc<Mutex<Observations>>,
    shutdown: CancellationToken,
    thread: Option<JoinHandle<()>>,
}
impl Fixture {
    fn origin(config: &FixtureConfig, run: &str) -> ProbeResultValue<(String, String)> {
        let origin = url::Url::parse(&config.origin)
            .map_err(|_| ProbeError::blocked("fixture origin invalid"))?;
        if origin.scheme() != "http"
            || origin.host_str().is_none()
            || origin.path() != "/"
            || origin.query().is_some()
            || origin.fragment().is_some()
            || !origin.username().is_empty()
            || origin.password().is_some()
        {
            return Err(ProbeError::blocked(
                "fixture needs an approved public HTTP origin",
            ));
        }
        if uuid::Uuid::parse_str(run).is_err() {
            return Err(ProbeError::blocked("fixture run identity is invalid"));
        }
        Ok((
            config.origin.trim_end_matches('/').into(),
            format!("/probe/{run}/"),
        ))
    }
    /// HTTP observations remain owned by the parent's listener.
    pub fn borrow(config: &FixtureConfig, run: &str) -> ProbeResultValue<Self> {
        let (origin, prefix) = Self::origin(config, run)?;
        Ok(Self {
            origin,
            prefix,
            requests: Arc::new(Mutex::new(Observations::default())),
            shutdown: CancellationToken::new(),
            thread: None,
        })
    }
    pub fn open(config: &FixtureConfig, run: &str, deadline: Instant) -> ProbeResultValue<Self> {
        let (origin, prefix) = Self::origin(config, run)?;
        let listener = TcpListener::bind(config.bind_address)
            .map_err(|_| ProbeError::blocked("approved fixture bind unavailable"))?;
        listener
            .set_nonblocking(true)
            .map_err(|_| ProbeError::blocked("fixture nonblocking mode unavailable"))?;
        let paths = Arc::new(Mutex::new(Observations::default()));
        let shutdown = CancellationToken::new();
        let stop = shutdown.clone();
        let recorded = Arc::clone(&paths);
        let route = prefix.clone();
        let thread=std::thread::Builder::new().name("kernel-owned-fixture".into()).spawn(move|| {
            while !stop.is_cancelled() && Instant::now()<deadline {
                let (mut stream,_)=match listener.accept(){Ok(pair)=>pair,Err(error) if error.kind()==std::io::ErrorKind::WouldBlock=>{std::thread::sleep(Duration::from_millis(5));continue;},Err(_)=>break};
                let _=stream.set_read_timeout(Some(Duration::from_secs(2)));let _=stream.set_write_timeout(Some(Duration::from_secs(2)));
                let mut request=Vec::new();let mut buffer=[0;1024];
                while request.len()<MAX_HEADER_BYTES && !request.windows(4).any(|w|w==b"\r\n\r\n") {
                    let remaining = (MAX_HEADER_BYTES - request.len()).min(buffer.len());
                    match stream.read(&mut buffer[..remaining]){Ok(0)=>break,Ok(count)=>request.extend_from_slice(&buffer[..count]),Err(_)=>break}
                }
                let Some(observed)=parse_request(&request, &route) else {let _=stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length:0\r\nConnection:close\r\n\r\n");continue;};
                let path=observed.path.clone();
                if let Ok(mut paths)=recorded.lock(){
                    let bytes=observed.path.len()+observed.user_agent.as_ref().map_or(0,String::len)+observed.accept_language.as_ref().map_or(0,String::len);
                    if paths.requests.len()<65536 && paths.bytes.saturating_add(bytes)<=MAX_OBSERVATION_BYTES {
                        paths.bytes+=bytes;
                        paths.requests.push(observed);
                    } else {paths.overflow=true;}
                }
                let (content_type,body,extra)=if path==format!("{route}file") {
                    ("application/octet-stream",DOWNLOAD_BYTES.to_vec(),"Content-Disposition: attachment; filename=probe.txt\r\n")
                }else if path==format!("{route}worker.js") {
                    ("application/javascript",b"setInterval(()=>postMessage('probe-worker'),100);".to_vec(),"")
                }else if path==format!("{route}iframe") {
                    ("text/html",b"<!doctype html><div id=frame-marker>owned iframe</div>".to_vec(),"")
                }else {
                    let html=format!(r#"<!doctype html><meta charset=utf-8><script>
const first={{width:innerWidth,height:innerHeight,device_scale_factor:devicePixelRatio,locale:navigator.language,intl_locale:Intl.DateTimeFormat().resolvedOptions().locale,number_locale:Intl.NumberFormat().resolvedOptions().locale,timezone:Intl.DateTimeFormat().resolvedOptions().timeZone,user_agent:navigator.userAgent}};
if(location.pathname.endsWith('/isolation_a')){{localStorage.setItem('browserd_kernel_isolation','owned-a');document.cookie='browserd_kernel_isolation=owned-a;path=/';document.title=(localStorage.getItem('browserd_kernel_isolation')==='owned-a'&&document.cookie.includes('owned-a'))?'isolation-a-seeded':'isolation-a-failed';}}
if(location.pathname.endsWith('/isolation_b')){{document.title=(localStorage.getItem('browserd_kernel_isolation')===null&&!document.cookie.includes('owned-a'))?'isolation-clean':'isolation-leaked';}}
addEventListener('DOMContentLoaded',()=>document.getElementById('emulation').textContent=JSON.stringify(first));
</script><style>@keyframes move{{from{{transform:translateX(0);background:red}}to{{transform:translateX(300px);background:blue}}}}#marker{{width:80px;height:80px;animation:move .4s infinite alternate}}</style><div id=marker>owned kernel fixture</div><pre id=emulation></pre><a id=download href="{route}file">download</a><iframe src="{route}iframe"></iframe><script>window.probeWorker=new Worker('{route}worker.js');window.probeCounter=0;setInterval(()=>window.probeCounter++,20);</script>"#);
                    ("text/html; charset=utf-8",html.into_bytes(),"")
                };
                let headers=format!("HTTP/1.1 200 OK\r\nContent-Type:{content_type}\r\nContent-Length:{}\r\nCache-Control:no-store\r\n{extra}Connection:close\r\n\r\n",body.len());
                let _=stream.write_all(headers.as_bytes()).and_then(|()|stream.write_all(&body));
            }
        }).map_err(|_|ProbeError::blocked("fixture thread unavailable"))?;
        Ok(Self {
            origin,
            prefix,
            requests: paths,
            shutdown,
            thread: Some(thread),
        })
    }
    pub fn url(&self, kind: &str) -> ProbeResultValue<String> {
        if kind.is_empty()
            || kind.len() > 64
            || !kind.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            return Err(ProbeError::failed("invalid owned fixture kind"));
        }
        Ok(format!("{}{}{kind}", self.origin, self.prefix))
    }
    pub fn saw(&self, kind: &str) -> bool {
        self.requests.lock().is_ok_and(|paths| {
            !paths.overflow
                && paths
                    .requests
                    .iter()
                    .any(|p| p.path == format!("{}{kind}", self.prefix))
        })
    }
    pub fn request_headers(&self, kind: &str) -> ProbeResultValue<Vec<FixtureRequest>> {
        self.url(kind)?;
        let observed = self
            .requests
            .lock()
            .map_err(|_| ProbeError::failed("fixture HTTP observations unavailable"))?;
        if observed.overflow {
            return Err(ProbeError::failed(
                "fixture HTTP observation bound exceeded",
            ));
        }
        let path = format!("{}{kind}", self.prefix);
        let requests = observed
            .requests
            .iter()
            .filter(|request| request.path == path)
            .cloned()
            .collect::<Vec<_>>();
        if requests.is_empty() {
            return Err(ProbeError::failed(
                "current-run fixture HTTP request was not witnessed",
            ));
        }
        Ok(requests)
    }
    pub fn finish(&mut self) -> bool {
        self.shutdown.cancel();
        self.thread
            .take()
            .is_none_or(|thread| thread.join().is_ok())
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

fn parse_request(bytes: &[u8], prefix: &str) -> Option<FixtureRequest> {
    if bytes.len() > MAX_HEADER_BYTES || !bytes.windows(4).any(|window| window == b"\r\n\r\n") {
        return None;
    }
    let request = std::str::from_utf8(bytes).ok()?;
    let mut lines = request.split("\r\n");
    let mut first = lines.next()?.split(' ');
    if first.next() != Some("GET") {
        return None;
    }
    let path = first.next()?;
    if !path.starts_with(prefix)
        || path.len() > 512
        || path.bytes().any(|byte| byte.is_ascii_control())
        || !matches!(first.next(), Some("HTTP/1.0" | "HTTP/1.1"))
        || first.next().is_some()
    {
        return None;
    }
    let mut observed = FixtureRequest {
        path: path.into(),
        user_agent: None,
        accept_language: None,
    };
    for line in lines {
        if line.is_empty() {
            break;
        }
        let (name, value) = line.split_once(':')?;
        let value = value.trim();
        if value.len() > 1024 || value.bytes().any(|byte| byte.is_ascii_control()) {
            return None;
        }
        let slot = if name.eq_ignore_ascii_case("user-agent") {
            Some(&mut observed.user_agent)
        } else if name.eq_ignore_ascii_case("accept-language") {
            Some(&mut observed.accept_language)
        } else {
            None
        };
        if let Some(slot) = slot
            && slot.replace(value.into()).is_some()
        {
            return None;
        }
    }
    Some(observed)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]
    use super::*;
    #[test]
    fn current_run_headers_are_bounded_and_duplicate_headers_are_rejected() {
        let prefix = "/probe/current/";
        let request=b"GET /probe/current/emulation HTTP/1.1\r\nUser-Agent: exact-ua\r\nAccept-Language: ko-KR,ko;q=0.9\r\n\r\n";
        let observed = parse_request(request, prefix);
        assert!(
            observed.is_some_and(|request| request.user_agent.as_deref() == Some("exact-ua")
                && request.accept_language.as_deref() == Some("ko-KR,ko;q=0.9"))
        );
        assert!(parse_request(request, "/probe/stale/").is_none());
        assert!(parse_request(b"GET /probe/current/emulation HTTP/1.1\r\nUser-Agent: first\r\nuser-agent: second\r\n\r\n",prefix).is_none());
        assert!(
            parse_request(
                b"GET /probe/current/emulation HTTP/1.1\r\nUser-Agent: incomplete",
                prefix
            )
            .is_none()
        );
        assert!(parse_request(&vec![b'x'; MAX_HEADER_BYTES + 1], prefix).is_none());
    }
    #[test]
    fn borrowed_fixture_reuses_occupied_origin_without_listener_or_observations() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .unwrap_or_else(|error| panic!("local fixture control: {error}"));
        let address = listener
            .local_addr()
            .unwrap_or_else(|error| panic!("local fixture address: {error}"));
        let config = FixtureConfig {
            bind_address: address,
            origin: format!("http://{address}/"),
            host_direct_address: address,
            private_direct_address: address,
        };
        let run = uuid::Uuid::new_v4().to_string();
        let mut borrowed = Fixture::borrow(&config, &run)
            .unwrap_or_else(|error| panic!("borrowed fixture: {}", error.reason()));
        assert_eq!(
            borrowed.url("worker").ok(),
            Some(format!("http://{address}/probe/{run}/worker"))
        );
        assert!(!borrowed.saw("worker"));
        assert!(borrowed.request_headers("worker").is_err());
        assert!(borrowed.finish());
    }
    #[test]
    fn live_fixture_retains_only_matching_run_request_headers() {
        let control = TcpListener::bind("127.0.0.1:0")
            .unwrap_or_else(|error| panic!("fixture port: {error}"));
        let address = control
            .local_addr()
            .unwrap_or_else(|error| panic!("fixture address: {error}"));
        drop(control);
        let config = FixtureConfig {
            bind_address: address,
            origin: format!("http://{address}/"),
            host_direct_address: address,
            private_direct_address: address,
        };
        let run = uuid::Uuid::new_v4().to_string();
        let mut fixture = Fixture::open(&config, &run, Instant::now() + Duration::from_secs(5))
            .unwrap_or_else(|error| panic!("fixture open: {}", error.reason()));
        let mut stream = std::net::TcpStream::connect(address)
            .unwrap_or_else(|error| panic!("fixture connect: {error}"));
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap_or_else(|error| panic!("fixture timeout: {error}"));
        stream.write_all(format!("GET /probe/{run}/emulation HTTP/1.1\r\nHost: {address}\r\nUser-Agent: live-ua\r\nAccept-Language: ko-KR,ko;q=0.9\r\n\r\n").as_bytes()).unwrap_or_else(|error|panic!("fixture request: {error}"));
        let mut response = Vec::new();
        stream
            .take(16384)
            .read_to_end(&mut response)
            .unwrap_or_else(|error| panic!("fixture response: {error}"));
        assert!(response.starts_with(b"HTTP/1.1 200 OK"));
        let observed = fixture.request_headers("emulation");
        assert!(observed.is_ok_and(|requests| requests.len() == 1
            && requests[0].path == format!("/probe/{run}/emulation")
            && requests[0].user_agent.as_deref() == Some("live-ua")
            && requests[0].accept_language.as_deref() == Some("ko-KR,ko;q=0.9")));
        assert!(fixture.request_headers("unvisited").is_err());
        assert!(fixture.finish());
    }
}
