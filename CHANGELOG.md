# Changelog

## 0.1.1 — 2026-08-04

### Fixed

**`sg.sensitive-port-open` graded 9 ports where it should have graded 50.**

The port table held SSH, RDP, and seven database ports. A security group
exposing any of the following to `0.0.0.0/0` produced **no finding at all**:

```
21 FTP · 23 Telnet · 135 MSRPC · 137/139 NetBIOS · 161 SNMP · 389/636 LDAP
445 SMB · 943/945 OpenVPN · 1521 Oracle · 2049 NFS · 2181 ZooKeeper
2375/2376 Docker API · 2379/2380 etcd · 3000 Grafana · 4505/4506 SaltStack
5601 Kibana · 5672 AMQP · 5900 VNC · 5984 CouchDB · 6443 Kubernetes API
7001 WebLogic · 8000/8080/8443/8888 admin · 8086 InfluxDB · 9000 SonarQube
9042 Cassandra · 9090 Prometheus · 9092 Kafka · 9300 Elasticsearch transport
10250 kubelet · 15672 RabbitMQ management · 27018 MongoDB shard
50070 Hadoop NameNode
```

Forty-one ports, including several that are a direct path to the host or to
the whole cluster. Analysing such a group returned zero findings, which the
consuming UI presents as a clean result — the worst failure mode available to
a security tool.

All forty-one are now graded, each with an explanation of why the port
matters. The severity remains `null`, as it is for every rule in this package:
`describe-security-groups` output does not say whether the group is attached
to anything, and this package does not guess.

### Added

- A parity test in the CloudArq repository that reads the production scanner's
  own port table and fails if any port it grades is missing here. The
  divergence above happened because nothing was checking; a hand-maintained
  list in a second language needs a machine to keep it honest.

### Notes

No API change. `analyzeAll` and every exported type are unchanged — existing
callers get more findings on the same input, and none of the previously
reported findings have changed shape.
