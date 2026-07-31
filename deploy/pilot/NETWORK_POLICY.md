# Controlled-pilot network boundary

Status: **PENDING customer firewall review and target verification**. Compose
selects pre-created networks; it does not make an unfenced egress bridge safe.

## Required segmentation

| Network | Allowed members | Allowed destination |
|---|---|---|
| `control` | API, TLS proxy, Prometheus, runtime, notifications | project-internal control-plane ports only |
| `data` | PostgreSQL and explicitly selected DB clients | project-internal PostgreSQL only |
| `camera-lan` | the one shared runtime | exact customer NVR/camera CIDRs and approved RTSP/DNS/NTP paths only |
| `storage-egress` | retention, runtime, backup, API preview reader | reviewed Kazakhstan object-storage CIDRs on TCP 443 only |
| `notification-egress` | notifications overlay only | customer-approved Telegram/connector CIDRs on TCP 443 only |
| `acceptance-loopback` | acceptance controller only | no external route; host exposure is loopback only |

The API has no general internet route. When the runtime overlay is explicitly
selected, its preview reader joins `storage-egress` with distinct credentials
limited to read-only ranged object access under the reviewed site preview
prefix. It must not list the bucket or create, overwrite, or delete objects.
PostgreSQL has no egress route. The NVIDIA runtime does not use host
networking: it joins separate camera, control, data, and storage networks. The
acceptance controller never joins the camera/data networks and never receives
`docker.sock`. Its launch-bound `acceptance-channel` is a private,
quota-bounded bind path, not a network or Docker control surface.

Backup, restore, administrator bootstrap, Telegram, runtime, and acceptance
services exist only in their explicit Compose overlays. Leave an overlay
unselected when its network, secrets, or approval is incomplete.

## Camera network

Resolve and record every lawful camera/NVR, internal DNS, and NTP destination.
Create a dedicated bridge; the example subnet is not a site authorization:

```bash
docker network create \
  --driver bridge \
  --subnet 172.31.40.0/24 \
  kuzet-camera-lan

docker network inspect kuzet-camera-lan \
  --format '{{with index .Options "com.docker.network.bridge.name"}}{{.}}{{end}}'
```

Set `PILOT_CAMERA_NETWORK=kuzet-camera-lan`. On the inspected bridge, allow
only the signed camera/NVR CIDRs and required RTSP transport ports, plus the
approved internal DNS/NTP endpoints. Install a terminal drop rule. Do not
allow general internet access, east-west access to unlisted cameras, or
operator workstations.

## Kazakhstan storage network

Resolve the exact reviewed storage endpoint through the customer's approved
DNS path. Record the endpoint, certificate identity, Kazakhstan residency
evidence, and resulting CIDRs in the signed site change, then create:

```bash
docker network create \
  --driver bridge \
  --subnet 172.31.41.0/28 \
  kuzet-storage-egress

docker network inspect kuzet-storage-egress \
  --format '{{with index .Options "com.docker.network.bridge.name"}}{{.}}{{end}}'
```

Set `PILOT_STORAGE_EGRESS_NETWORK=kuzet-storage-egress`. Using the inspected
bridge name and every reviewed destination CIDR, install accept rules before a
terminal drop. This example uses Docker's persistent `DOCKER-USER` chain; the
customer firewall owner must adapt it to the managed host policy:

```bash
export PILOT_STORAGE_BRIDGE=br-REPLACE_WITH_INSPECTED_ID
export PILOT_STORAGE_CIDR_1=203.0.113.8/32

sudo iptables -C DOCKER-USER -i "$PILOT_STORAGE_BRIDGE" \
  -p tcp -d "$PILOT_STORAGE_CIDR_1" --dport 443 \
  -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT \
  || sudo iptables -I DOCKER-USER 1 -i "$PILOT_STORAGE_BRIDGE" \
    -p tcp -d "$PILOT_STORAGE_CIDR_1" --dport 443 \
    -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT

sudo iptables -C DOCKER-USER -i "$PILOT_STORAGE_BRIDGE" -j DROP \
  || sudo iptables -A DOCKER-USER -i "$PILOT_STORAGE_BRIDGE" -j DROP
```

Repeat the accept rule for each signed CIDR. Never substitute `0.0.0.0/0`.

The API preview identity has exactly one object-level read action, scoped to
the reviewed site preview prefix: `s3:GetObjectVersion`. It also has exactly
two bucket-level read-only actions
on the reviewed bucket ARN: `s3:GetBucketVersioning` and
`s3:GetLifecycleConfiguration`. Those bucket-level actions are required to
fail closed unless immutable versioning and the reviewed finite lifecycle are
observable. Do not grant `s3:ListBucket`, any `s3:PutObject*`,
`s3:DeleteObject*`, ACL mutation, lifecycle mutation, or versioning mutation.
Archive the effective policy and positive/negative authorization probes; a
generic read-only policy name is not evidence.
The preview rule must use only the exact preview prefix, exact `Days`, and
exact `NoncurrentDays`; `NewerNoncurrentVersions`, tag, size, or other
narrowing fields are rejected.

The runtime writer identity is separate. On the reviewed bucket it has only
`s3:GetBucketVersioning` and `s3:GetLifecycleConfiguration`; under the exact
reviewed evidence prefix it has only `s3:GetObject` and `s3:PutObject`.
It must fail closed if the full-prefix lifecycle is not
exactly the reviewed current-version retention with `NoncurrentDays=1`.
The rule filter must contain only the exact prefix, `Expiration` only `Days`,
and `NoncurrentVersionExpiration` only `NoncurrentDays`; a
`NewerNoncurrentVersions` or tag/size narrowing field is invalid.
Prove that it cannot read a named noncurrent version, list versions, delete
any version, mutate bucket policy, lifecycle, versioning, or ACLs, write
another prefix, or read another bucket.

The retention identity has the same two bucket-policy reads plus
prefix-conditioned `s3:ListBucketVersions`. Under the reviewed evidence
prefix it has only `s3:GetObjectVersion` and `s3:DeleteObjectVersion`; under
the separate reviewed audit-archive prefix it additionally has only
`s3:GetObject` and `s3:PutObject`. It does not receive `s3:DeleteObject`,
evidence-prefix write, archive deletion, cross-prefix access, or any
lifecycle/versioning/ACL mutation. Archive positive probes for exact-version
lookup, checksum-bound deletion, post-delete verification, preview orphan
listing, and immutable archive publication, plus negative probes for every
denied operation.

Every writer grant above is conditional-create only. Archive the effective
bucket/resource policy proving that `s3:PutObject` is denied unless the
request carries the provider-verified equivalent of
`s3:if-none-match = "*"`. With each runtime evidence, runtime preview, and
retention archive identity, run three separate probes: one positive
conditional create; one same-key, different-byte conditional write that must
return `409`/`412`; and one same-key write without the header that must return
`403`/authorization denial. After both negative probes, an exact
HEAD/GET/version receipt must prove that the original current object and
metadata are unchanged. This separates atomic provider precondition behavior
from bucket-policy enforcement. If the selected
Kazakhstan S3-compatible provider cannot prove and enforce that condition,
storage acceptance is **BLOCKED** until an equivalent immutable write gateway
or reviewed object-lock design is in place.

When the reviewed storage mode is `aws:kms`, the API preview, runtime, and
retention identities receive only the key-scoped KMS operations their allowed
object actions require:
`kms:GenerateDataKey` and `kms:Decrypt` for the authorized SSE-KMS write or
checksum-verifying HEAD path. No wildcard KMS resource or key-management action
is allowed.

## Notification network

Create `notification-egress` independently only after the named customer and
network approvals exist. Allow only the connector's reviewed HTTPS CIDRs.
Set `PILOT_NOTIFICATION_EGRESS_NETWORK` to that pre-created network and set
both `PILOT_TELEGRAM_CUSTOMER_APPROVED=true` and
`PILOT_TELEGRAM_NETWORK_APPROVED=true`. If DNS/CDN addressing cannot be
constrained under the customer's policy, do not select
`docker-compose.telegram.yml`; use the documented human fallback route.

Storage approval does not authorize notification egress, and notification
approval does not authorize storage or camera access.

## Verification and evidence

Before activation, archive:

- network inspect output and immutable network IDs/configuration hashes;
- the host firewall export and named approving owner;
- exact allowed CIDRs, ports, DNS/NTP paths, and endpoint certificates;
- successful access to each approved endpoint;
- failed access to representative unapproved camera, storage, and internet
  destinations;
- proof that API/PostgreSQL cannot reach unapproved internet destinations;
- proof that the API preview reader can make bounded ranged reads only and
  cannot list, write, overwrite, or delete storage objects;
- proof that only the shared runtime joins `camera-lan`;
- proof that only selected storage clients join `storage-egress`;
- proof that the notification network and worker are absent when unapproved;
- proof that acceptance binds only to `127.0.0.1` and has no Docker socket.

Any endpoint, CIDR, network ID, firewall rule, host, source, or overlay change
invalidates this review and the corresponding acceptance evidence.
