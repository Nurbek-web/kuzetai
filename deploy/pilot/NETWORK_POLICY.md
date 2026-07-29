# Controlled-pilot egress boundary

The API and PostgreSQL services have no internet route. The retention worker
needs TCP 443 only to the reviewed Kazakhstan object-storage endpoint, and the
notification worker gets a separate route only after customer and network
approval. Compose requires both egress networks to be pre-created; an
unfenced bridge is a pending deployment gate, not an accepted default.

Resolve the storage endpoint through the customer's approved DNS path, record
the resulting Kazakhstan CIDRs in the signed site change, then create a
dedicated bridge:

```bash
docker network create \
  --driver bridge \
  --subnet 172.31.41.0/28 \
  kuzet-storage-egress

docker network inspect kuzet-storage-egress \
  --format '{{with index .Options "com.docker.network.bridge.name"}}{{.}}{{end}}'
```

Set `PILOT_STORAGE_EGRESS_NETWORK=kuzet-storage-egress`. Using the bridge name
printed above and every reviewed destination CIDR, install accept rules before
the terminal drop. The example uses Docker's persistent `DOCKER-USER` chain;
the customer firewall owner must adapt it to the site's managed policy:

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
Persist the rules using the customer's host-firewall mechanism and verify from
the retention container that the reviewed endpoint succeeds while an
unapproved HTTPS destination fails. Record the network inspect output,
firewall rule export, endpoint certificate identity, and test results in the
acceptance pack.

Create the notification egress network independently and allow only the
customer-approved connector endpoint. Leave the notification service stopped
and its approval variables unset when this gate is not complete.
