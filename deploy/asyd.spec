Name:           asyd
Version:        0.3.0
Release:        1%{?dist}
Summary:        ASys Daemon — Agentic System Interface
License:        Apache-2.0
URL:            https://github.com/vincentping/asys
Source0:        asyd-%{version}.tar.gz

BuildRequires:  gcc make
%global debug_package %{nil}
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd

%description
asyd is the reference daemon for the ASys (Agentic System Interface)
protocol. It accepts, authenticates, and executes ASys binary commands
from authorized AI agents over TCP port 7816, using the Noise IK
handshake (Curve25519 + ChaCha20-Poly1305 + BLAKE2b) for transport
security and a public-key whitelist for agent authorization.

%prep
%setup -q

%build
make asyd

%install
install -D -m 0755 bin/asyd          %{buildroot}/usr/sbin/asyd
install -D -m 0644 deploy/asyd.service \
    %{buildroot}/usr/lib/systemd/system/asyd.service

%post
%systemd_post asyd.service

%preun
%systemd_preun asyd.service

%postun
%systemd_postun_with_restart asyd.service

%files
/usr/sbin/asyd
/usr/lib/systemd/system/asyd.service

%changelog
* Mon Apr 06 2026 Vincent Ping <vincentping@gmail.com> - 0.3.0-1
- Phase 5 open-source release
- asys.isa v1.0: SYS_CAPS/SYS_HELLO/SYS_STATUS/SYS_PROCS/TASK_QUERY/PROC_THROTTLE/SVC_RESTART
- Trust model: public-key whitelist (/etc/asyd/authorized_agents)
- SIGHUP hot-reload of agent whitelist (async-signal-safe)
- Zero external dependencies
