# Descles edge on AWS (one stack)

[`descles-edge.yaml`](descles-edge.yaml) runs the edge in **your** AWS account: nothing to operate beyond a
CloudFormation stack. Your provider key and edge token go to Secrets Manager in that account and are
read only by the edge instance. Descles receives nothing in standalone mode and, in managed mode, only
the metadata in [DATA-FLOWS](../../docs/DATA-FLOWS.md).

```bash
aws cloudformation create-stack --stack-name descles-edge --capabilities CAPABILITY_IAM \
  --template-body file://descles-edge.yaml --parameters file://params.json
```

Or open CloudFormation in the console, choose **Create stack**, upload the template, and fill in the form.

## What it creates

- One Graviton instance (`t4g.small` by default) on Amazon Linux 2023: IMDSv2 only, encrypted disk, no
  SSH; use Systems Manager Session Manager. At first boot it installs Docker, downloads the `descles` CLI
  from the chosen release, checks it against the release's `SHA256SUMS`, pins the edge image by the digest
  published with the release, and runs `descles edge init` and `descles edge up`.
- HTTPS in front of it, one of two ways:
  - **Your domain** (`DomainName`, `HostedZoneId`, `VpcId`, two `SubnetIds`): an Application Load Balancer
    with an ACM certificate and a Route 53 record. `AllowedCidr` limits who can reach it.
  - **No domain** (leave `DomainName` empty): a small VPC of its own and a CloudFront distribution with a
    VPC origin, so you get `https://xxxx.cloudfront.net` and CloudFront reaches the instance privately. The
    instance accepts traffic only from CloudFront's origin-facing addresses.
- Three secrets: the provider key, the edge token (managed mode), and a generated secret with the edge's
  admin token (and, standalone, the first agent key).

## Parameters

| Parameter | |
|---|---|
| `Mode` | `managed` (Descles control plane) or `standalone` (nothing reported) |
| `Provider`, `ProviderKey`, `OpenAIBase` | `anthropic`, or `openai` with any OpenAI-compatible base URL |
| `OrgId`, `BundleKey`, `EdgeToken` | Managed mode: from the Descles console; check the bundle key against the console before pasting |
| `ReleaseTag` | The edge release to run |
| `DomainName` and the rest | Optional, see above |

## After it is created

The stack outputs `EdgeURL`, `ApproverURL` and `GeneratedSecretArn`.

```bash
aws secretsmanager get-secret-value --secret-id <GeneratedSecretArn> --query SecretString --output text
# {"admin_token": "...", "agent_key": "vk_..."}   (agent_key only in standalone mode)

export ANTHROPIC_BASE_URL=<EdgeURL>/anthropic      # or OPENAI_BASE_URL=<EdgeURL>/v1
export ANTHROPIC_AUTH_TOKEN=<agent key>
descles doctor --edge <EdgeURL>
```

In managed mode, agent keys come from the Descles console (members create them within their ceiling).

## Limits

- One instance, no automatic failover; records and approvals live on its disk. Take EBS snapshots if you
  need them, and remember a snapshot keeps approval arguments that were pending when it was taken.
- Without a domain, CloudFront waits at most 60 seconds for a response to start. Streamed model responses
  are fine; a long non-streamed request can time out, so prefer streaming or use your own domain.
- Without a domain, the stack needs the CloudFront origin-facing prefix list id for your Region. The
  template knows it for 17 Regions; elsewhere pass `CloudFrontPrefixListId`
  (`aws ec2 describe-managed-prefix-lists --filters Name=prefix-list-name,Values=com.amazonaws.global.cloudfront.origin-facing`).
- Upgrading: changing `ReleaseTag` on an existing stack does not upgrade the running edge, because the
  setup runs only at first boot. Either create a new stack (new admin token, fresh local records), or on
  the instance set the new release's image digest in `/opt/descles-edge/compose.yml` and run
  `docker compose -f /opt/descles-edge/compose.yml up -d`.

Tested end to end on 2026-09-27 in ap-northeast-1 (standalone, no domain, an OpenAI-compatible provider):
HTTPS through CloudFront, streamed and non-streamed model calls, rejected wrong keys, and no direct access
to the instance.
