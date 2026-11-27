FROM scratch
COPY bifroest /usr/bin/bifroest
COPY fixture /fixture
COPY passwd /etc/passwd
COPY group /etc/group
USER 10001:10001
ENTRYPOINT ["/fixture", "-test.run=^TestKubernetesTLSBootstrap$", "-test.parallel=1", "-test.v", "-test.timeout=5m"]
